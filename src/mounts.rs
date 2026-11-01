//! Root migration and pseudo-filesystem setup (child side).
//!
//! The child pivots into either a plain rootfs directory or an OverlayFS
//! (lower = read-only image/rootfs, disk upper = container writes). When an
//! overlay mount is not permitted (restricted rootless hosts), the fallback is
//! a full copy of the lower into the per-run directory.
use crate::error::{last_err, ZResult};
use crate::fsutil;
use crate::syscalls;
use crate::trace;
use libc::{
    MNT_DETACH, MS_BIND, MS_NODEV, MS_NOEXEC, MS_NOSUID, MS_PRIVATE, MS_RDONLY, MS_REC,
    MS_RELATIME, MS_REMOUNT, MS_STRICTATIME,
};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// Sensitive procfs/sysfs paths that are masked inside the container
/// (maskedPaths, per OCI runtime convention).
const MASKED_PATHS: &[&str] = &[
    "/proc/kcore",
    "/proc/keys",
    "/proc/timer_list",
    "/proc/sched_debug",
    "/proc/latency_stats",
    "/sys/firmware",
];

const READONLY_PATHS: &[&str] = &["/proc/sys", "/proc/sysrq-trigger", "/proc/irq", "/proc/bus"];

pub(crate) const DEVICE_NODES: &[(&str, u32, u32)] = &[
    ("/dev/null", 1, 3),
    ("/dev/zero", 1, 5),
    ("/dev/full", 1, 7),
    ("/dev/random", 1, 8),
    ("/dev/urandom", 1, 9),
    ("/dev/tty", 5, 0),
];

/// OverlayFS component directories for a per-container writable filesystem.
#[derive(Debug, Clone)]
pub struct OverlayPaths {
    /// Read-only base (image rootfs or unpacked rootfs directory).
    pub lower: PathBuf,
    /// Container writes land here (disk).
    pub upper: PathBuf,
    /// Overlay workdir (kernel internal; same fs as upper).
    pub work: PathBuf,
    /// Mount point the child pivots into.
    pub merged: PathBuf,
    /// Mount a per-run tmpfs over the overlay directory before mounting overlay.
    pub tmpfs_upper: bool,
}

/// A host path bind-mounted into the container rootfs before pivot_root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMount {
    /// Canonicalized host path. Empty until a named volume is resolved.
    pub source: PathBuf,
    /// Absolute path inside the container (without `..` components).
    pub target: PathBuf,
    pub readonly: bool,
    /// Named-volume source when `HOST` was not an absolute host path.
    pub named: Option<String>,
    /// Operator's original argument, used to rebuild restart/service commands
    /// without replacing a volume name with a store-local path.
    pub raw: String,
}

/// Parse Docker-style simple bind syntax: `HOST:CONTAINER[:ro|rw]`. Named
/// volumes and colon-containing paths are not accepted; this keeps parsing
/// unambiguous and avoids accidentally treating a registry-style volume name
/// as a host path.
pub fn parse_bind(value: &str) -> Result<BindMount, String> {
    let mut parts = value.split(':');
    let Some(host) = parts.next() else {
        return Err("-v: HOST:CONTAINER is required".to_string());
    };
    let Some(container) = parts.next() else {
        return Err(format!("-v: HOST:CONTAINER is required ('{value}')"));
    };
    let mode = parts.next().unwrap_or("rw");
    if parts.next().is_some() {
        return Err(format!(
            "-v: unsupported volume '{value}' (colon-containing paths are not supported)"
        ));
    }
    let readonly = match mode {
        "" | "rw" => false,
        "ro" => true,
        other => return Err(format!("-v: unsupported mode '{other}' (rw|ro)")),
    };
    validate_container_target("-v", container)?;

    // Docker accepts either an absolute bind source or a named volume. Named
    // sources are resolved by the caller against the active data root because
    // `parse_run_args` is also used by commands that must not create storage.
    let (source, named) = if host.starts_with('/') {
        let source = std::fs::canonicalize(host)
            .map_err(|e| format!("-v: host path '{host}' does not exist: {e}"))?;
        let meta = std::fs::metadata(&source)
            .map_err(|e| format!("-v: host path '{host}' is not accessible: {e}"))?;
        if !meta.is_dir() && !meta.is_file() {
            return Err(format!(
                "-v: host path '{host}' must be a regular file or directory"
            ));
        }
        (source, None)
    } else {
        validate_volume_name(host)?;
        (PathBuf::new(), Some(host.to_string()))
    };

    Ok(BindMount {
        source,
        target: PathBuf::from(container),
        readonly,
        named,
        raw: value.to_string(),
    })
}

/// Validate an absolute container mount target before it is persisted or
/// passed to the child. Image metadata is untrusted too, so image-declared
/// volumes use the same absolute/root/`.`/`..` checks as operator mounts.
pub fn validate_container_target(option: &str, target: &str) -> Result<(), String> {
    if !target.starts_with('/') {
        return Err(format!(
            "{option}: container path '{target}' must be absolute"
        ));
    }
    if target == "/" {
        return Err(format!(
            "{option}: refusing to mount over the container root"
        ));
    }
    if !Path::new(target)
        .components()
        .skip(1)
        .all(|component| matches!(component, std::path::Component::Normal(_)))
    {
        return Err(format!(
            "{option}: container path '{target}' must be absolute without '.' or '..'"
        ));
    }
    Ok(())
}

/// Validate Docker-style volume names. Unlike host paths, these become one
/// directory component under the data root, so traversal and separator tricks
/// are rejected before they can escape the managed volume tree.
pub fn validate_volume_name(name: &str) -> Result<(), String> {
    let valid = (1..=128).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
        && !matches!(name, "." | "..");
    if valid {
        Ok(())
    } else {
        Err(format!(
            "-v: invalid volume name '{name}' (use 1-128 letters, digits, '_', '.' or '-')"
        ))
    }
}

/// A per-container tmpfs mount requested with `--tmpfs PATH[:opts]`.
/// `raw` keeps the operator's exact spelling so `restart` / `generate-service`
/// can reproduce the launch arguments verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TmpfsMount {
    /// Absolute container path (no `.`/`..` components).
    pub target: PathBuf,
    /// Mount data (e.g. "size=16m,mode=1777"); empty for kernel defaults.
    pub data: String,
    /// Mount the tmpfs read-only.
    pub readonly: bool,
    /// The original `--tmpfs` argument.
    pub raw: String,
}

/// The device-node type passed through by `--device`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    Char,
    Block,
}

/// Docker-compatible device permissions (`rwm`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevicePermissions {
    pub read: bool,
    pub write: bool,
    pub mknod: bool,
}

impl DevicePermissions {
    pub const FULL: Self = Self {
        read: true,
        write: true,
        mknod: true,
    };

    pub fn is_full(self) -> bool {
        self.read && self.write && self.mknod
    }
}

/// A host device exposed through `--device HOST[:CONTAINER[:PERMISSIONS]]`.
///
/// `source` is canonicalized to validate the actual device, while `target`
/// and `raw` retain the operator-visible request. Rootful runs recreate the
/// node with `mknod`; rootless runs bind an O_PATH handle opened before pivot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceMount {
    pub source: PathBuf,
    pub target: PathBuf,
    pub permissions: DevicePermissions,
    pub kind: DeviceKind,
    pub major: u32,
    pub minor: u32,
    /// Original CLI token, preserved for restart and service generation.
    pub raw: String,
}

/// Parse Docker's `--device HOST[:CONTAINER[:PERMISSIONS]]` syntax.
///
/// A two-field form accepts either a container target (absolute path) or a
/// permission set, so both `--device /dev/fuse:/dev/fuse` and
/// `--device /dev/fuse:rw` are unambiguous. Only character and block devices
/// are accepted as sources.
pub fn parse_device(value: &str) -> Result<DeviceMount, String> {
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() > 3 {
        return Err(format!(
            "--device: invalid device '{value}' (HOST[:CONTAINER[:rwm]])"
        ));
    }
    let source = parts[0];
    if source.is_empty() || !source.starts_with('/') {
        return Err(format!("--device: host path '{source}' must be absolute"));
    }
    let (target, permissions) = match parts.as_slice() {
        [source] => (*source, DevicePermissions::FULL),
        [source, second] if second.starts_with('/') => (*second, DevicePermissions::FULL),
        [source, permissions] => (*source, parse_device_permissions(permissions)?),
        [_, target, permissions] => {
            if !target.starts_with('/') {
                return Err(format!(
                    "--device: container path '{target}' must be absolute"
                ));
            }
            (*target, parse_device_permissions(permissions)?)
        }
        _ => unreachable!("device field count was checked"),
    };
    if target == "/" {
        return Err("--device: refusing to mount over the container root".to_string());
    }
    if !Path::new(target)
        .components()
        .skip(1)
        .all(|component| matches!(component, std::path::Component::Normal(_)))
    {
        return Err(format!(
            "--device: container path '{target}' must be absolute without '.' or '..'"
        ));
    }

    let source = std::fs::canonicalize(source)
        .map_err(|error| format!("--device: host path '{source}' is not accessible: {error}"))?;
    let metadata = std::fs::metadata(&source)
        .map_err(|error| format!("--device: stat host path {}: {error}", source.display()))?;
    let file_type = metadata.file_type();
    let kind = if file_type.is_char_device() {
        DeviceKind::Char
    } else if file_type.is_block_device() {
        DeviceKind::Block
    } else {
        return Err(format!(
            "--device: host path {} must be a character or block device",
            source.display()
        ));
    };
    let rdev = metadata.rdev();
    let (major, minor) = device_numbers(rdev);

    Ok(DeviceMount {
        source,
        target: PathBuf::from(target),
        permissions,
        kind,
        major,
        minor,
        raw: value.to_string(),
    })
}

fn device_numbers(rdev: u64) -> (u32, u32) {
    let major = (((rdev >> 8) & 0xfff) | ((rdev >> 32) & !0xfff)) as u32;
    let minor = ((rdev & 0xff) | ((rdev >> 12) & !0xff)) as u32;
    (major, minor)
}

fn parse_device_permissions(value: &str) -> Result<DevicePermissions, String> {
    if value.is_empty() {
        return Err("--device: permissions cannot be empty (use rwm)".to_string());
    }
    let mut permissions = DevicePermissions {
        read: false,
        write: false,
        mknod: false,
    };
    for permission in value.chars() {
        let slot = match permission {
            'r' => &mut permissions.read,
            'w' => &mut permissions.write,
            'm' => &mut permissions.mknod,
            other => {
                return Err(format!(
                    "--device: invalid permission '{other}' (use r, w, or m)"
                ))
            }
        };
        if *slot {
            return Err(format!(
                "--device: duplicate permission '{permission}' in '{value}'"
            ));
        }
        *slot = true;
    }
    Ok(permissions)
}

/// Rootless device passthrough binds the host inode, so it cannot safely
/// emulate Docker's read/write subsets without mutating the host node. Require
/// full rwm access there; rootful runs recreate the node with filtered mode
/// bits.
pub fn validate_device_permissions(rootless: bool, devices: &[DeviceMount]) -> Result<(), String> {
    if rootless && devices.iter().any(|device| !device.permissions.is_full()) {
        return Err(
            "--device permission subsets require rootful execution; rootless runs inherit the \
             host node's rwm access"
                .to_string(),
        );
    }
    Ok(())
}

/// Reject duplicate container targets before starting a container. The child
/// can detect the collision too, but doing it during argument parsing produces
/// a clear error without allocating any runtime state.
pub fn validate_device_targets(devices: &[DeviceMount]) -> Result<(), String> {
    let mut targets = std::collections::BTreeSet::new();
    for device in devices {
        if !targets.insert(&device.target) {
            return Err(format!(
                "--device: duplicate container path {}",
                device.target.display()
            ));
        }
    }
    Ok(())
}

/// A parsed Docker-style `--mount` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountRequest {
    Bind(BindMount),
    Tmpfs(TmpfsMount),
}

/// Parse Docker's CSV-style `--mount` syntax for bind mounts, named volumes,
/// and tmpfs mounts. The result is normalized into the same internal types as
/// `-v` and `--tmpfs`, so restart metadata and generated services retain one
/// canonical representation.
///
/// Commas delimit fields and are therefore not supported inside paths. Bind
/// and volume sources are also rejected when they contain `:` because the
/// persisted `-v` form would be ambiguous.
pub fn parse_mount(value: &str) -> Result<MountRequest, String> {
    let mut fields = BTreeMap::new();
    for field in value.split(',') {
        if field.is_empty() {
            return Err(format!("--mount: empty field in '{value}'"));
        }
        let (raw_key, raw_value) = field.split_once('=').unwrap_or((field, ""));
        let (key, value) = match (raw_key, raw_value) {
            ("type", value) => ("type", value),
            ("source" | "src", value) => ("source", value),
            ("target" | "destination" | "dst", value) => ("target", value),
            ("readonly", "") => ("readonly", "true"),
            ("readonly", value) => ("readonly", value),
            ("ro", "") => ("readonly", "true"),
            ("rw", "") => ("readonly", "false"),
            ("ro" | "rw", _) => {
                return Err(format!(
                    "--mount: option '{raw_key}' does not accept a value"
                ))
            }
            ("tmpfs-size", value) => ("tmpfs-size", value),
            ("tmpfs-mode", value) => ("tmpfs-mode", value),
            (other, _) => return Err(format!("--mount: unsupported option '{other}'")),
        };
        if fields.insert(key, value).is_some() {
            return Err(format!("--mount: duplicate option '{key}'"));
        }
    }

    let mount_type = fields
        .remove("type")
        .ok_or_else(|| "--mount: type is required (bind|volume|tmpfs)".to_string())?;
    if mount_type.is_empty() {
        return Err("--mount: type cannot be empty".to_string());
    }

    let readonly = match fields.remove("readonly") {
        Some("true") => true,
        Some("false") => false,
        Some(value) => {
            return Err(format!(
                "--mount: readonly expects true or false, got '{value}'"
            ))
        }
        None => false,
    };

    match mount_type {
        "bind" | "volume" => {
            if fields.contains_key("tmpfs-size") || fields.contains_key("tmpfs-mode") {
                return Err(format!(
                    "--mount: tmpfs options are invalid for type={mount_type}"
                ));
            }
            let source = fields
                .remove("source")
                .filter(|source| !source.is_empty())
                .ok_or_else(|| format!("--mount: type={mount_type} requires source"))?;
            let target = fields
                .remove("target")
                .filter(|target| !target.is_empty())
                .ok_or_else(|| format!("--mount: type={mount_type} requires target"))?;
            reject_remaining_mount_fields(&fields)?;
            let source_is_absolute = Path::new(source).is_absolute();
            match mount_type {
                "bind" if !source_is_absolute => {
                    return Err("--mount: type=bind source must be an absolute host path".into())
                }
                "volume" if source_is_absolute => {
                    return Err(
                        "--mount: type=volume source must be a volume name, not a path".into(),
                    )
                }
                _ => {}
            }
            if source.contains(':') || source.contains(',') {
                return Err(
                    "--mount: source containing ':' or ',' cannot be persisted as -v".to_string(),
                );
            }
            if target.contains(':') || target.contains(',') {
                return Err("--mount: target containing ':' or ',' is not supported".to_string());
            }
            let mode = if readonly { "ro" } else { "rw" };
            let canonical = format!("{source}:{target}:{mode}");
            let mut mount = parse_bind(&canonical).map_err(|error| format!("--mount: {error}"))?;
            mount.raw = canonical;
            Ok(MountRequest::Bind(mount))
        }
        "tmpfs" => {
            if fields.remove("source").is_some() {
                return Err("--mount: type=tmpfs does not accept source".to_string());
            }
            let target = fields
                .remove("target")
                .filter(|target| !target.is_empty())
                .ok_or_else(|| "--mount: type=tmpfs requires target".to_string())?;
            let size = fields.remove("tmpfs-size");
            let mode = fields.remove("tmpfs-mode");
            reject_remaining_mount_fields(&fields)?;
            if target.contains(':') || target.contains(',') {
                return Err("--mount: target containing ':' or ',' is not supported".to_string());
            }
            let mut canonical = target.to_string();
            let mut options = Vec::new();
            if readonly {
                options.push("ro".to_string());
            }
            if let Some(size) = size {
                let bytes = crate::units::parse_size(size)
                    .map_err(|_| format!("--mount: invalid tmpfs-size '{size}'"))?;
                options.push(format!("size={bytes}"));
            }
            if let Some(mode) = mode {
                let parsed =
                    u32::from_str_radix(mode.trim_start_matches("0o"), 8).map_err(|_| {
                        format!("--mount: invalid tmpfs-mode '{mode}' (octal expected)")
                    })?;
                if parsed > 0o7777 {
                    return Err(format!("--mount: invalid tmpfs-mode '{mode}' (max 7777)"));
                }
                options.push(format!("mode={parsed:o}"));
            }
            if !options.is_empty() {
                canonical.push(':');
                canonical.push_str(&options.join(","));
            }
            let mut mount = parse_tmpfs(&canonical).map_err(|error| format!("--mount: {error}"))?;
            mount.raw = canonical;
            Ok(MountRequest::Tmpfs(mount))
        }
        other => Err(format!(
            "--mount: unsupported type '{other}' (bind|volume|tmpfs)"
        )),
    }
}

fn reject_remaining_mount_fields(fields: &BTreeMap<&str, &str>) -> Result<(), String> {
    match fields.keys().next() {
        Some(key) => Err(format!(
            "--mount: option '{key}' is invalid for this mount type"
        )),
        None => Ok(()),
    }
}

/// Parse Docker-style `--tmpfs PATH[:opts]`. Options are comma-separated
/// `key=value` pairs; `size` accepts the same binary byte units as resource
/// limits and is normalized to bytes, while `mode` is an octal value.
/// Anything else is rejected so a typo fails loudly instead of silently
/// mounting a tmpfs the operator did not ask for.
pub fn parse_tmpfs(value: &str) -> Result<TmpfsMount, String> {
    let (path, opts) = match value.split_once(':') {
        Some((p, o)) if !o.is_empty() => (p, Some(o)),
        _ => (value, None),
    };
    validate_container_target("--tmpfs", path)?;

    let mut data = String::new();
    let mut readonly = false;
    if let Some(opts) = opts {
        for opt in opts.split(',') {
            if opt.is_empty() {
                continue;
            }
            if opt == "ro" {
                readonly = true;
                continue;
            }
            if opt == "rw" {
                readonly = false;
                continue;
            }
            let Some((key, val)) = opt.split_once('=') else {
                return Err(format!(
                    "--tmpfs: unsupported option '{opt}' (key=value expected)"
                ));
            };
            match key {
                "size" => {
                    let bytes = crate::units::parse_size(val).map_err(|_| {
                        format!("--tmpfs: invalid size '{val}' (byte size expected)")
                    })?;
                    push_opt(&mut data, "size", &bytes.to_string());
                }
                "mode" => {
                    let parsed = u32::from_str_radix(val.trim_start_matches("0o"), 8)
                        .map_err(|_| format!("--tmpfs: invalid mode '{val}' (octal expected)"))?;
                    if parsed > 0o7777 {
                        return Err(format!("--tmpfs: invalid mode '{val}' (max 7777)"));
                    }
                    push_opt(&mut data, "mode", &format!("{parsed:o}"));
                }
                other => {
                    return Err(format!("--tmpfs: unsupported option '{other}'"));
                }
            }
        }
    }
    Ok(TmpfsMount {
        target: PathBuf::from(path),
        data,
        readonly,
        raw: value.to_string(),
    })
}

fn push_opt(data: &mut String, key: &str, value: &str) {
    if !data.is_empty() {
        data.push(',');
    }
    data.push_str(key);
    data.push('=');
    data.push_str(value);
}

/// Mount the operator's `--tmpfs` requests inside the container root (called
/// after pivot_root). Explicitly requested mounts are strict when rootful; a
/// restricted rootless host degrades with a warning, matching the pseudo-fs
/// setup above.
pub fn mount_extra_tmpfs(rootless: bool, mounts: &[TmpfsMount]) -> ZResult<()> {
    for m in mounts {
        let target = safe_target(Path::new("/"), &m.target)?;
        syscalls::mkdir_p(&target, 0o1777)?;
        let mut flags = MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME;
        if m.readonly {
            flags |= MS_RDONLY;
        }
        let data = if m.data.is_empty() {
            "mode=1777"
        } else {
            m.data.as_str()
        };
        require_or_warn(
            rootless,
            syscalls::mount(
                Some("tmpfs"),
                target.to_string_lossy(),
                Some("tmpfs"),
                flags,
                Some(data),
            ),
            &format!("--tmpfs {}", m.raw),
        )?;
    }
    Ok(())
}

/// Remount the container root read-only (`--read-only`). Called after every
/// setup write (/etc/hosts, resolv.conf) so the workload starts on a read-only
/// root; bind volumes and tmpfs mounts stay writable (separate mounts).
pub fn make_root_readonly(rootless: bool) -> ZResult<()> {
    let res = syscalls::mount(None, "/", None, MS_BIND | MS_REMOUNT | MS_RDONLY, None)
        .or_else(|_| syscalls::mount(None, "/", None, MS_REMOUNT | MS_RDONLY, None));
    match res {
        Ok(()) => Ok(()),
        Err(e) if rootless => {
            eprintln!(
                "zerun: warn: --read-only could not be enforced rootless ({e}); continuing read-write"
            );
            Ok(())
        }
        Err(e) => Err(e),
    }
}

pub struct RootfsConfig<'a> {
    /// Directory to pivot into (== overlay.merged when an overlay is used).
    pub rootfs: &'a Path,
    pub hostname: Option<&'a str>,
    /// Set the UTS hostname. False when sharing the host UTS namespace.
    pub set_hostname: bool,
    /// rootless (NEWUSER) cannot mknod; bind-mount whitelisted host devices instead.
    pub rootless: bool,
    /// When set, first make `rootfs` a writable overlay whose lower is read-only.
    pub overlay: Option<&'a OverlayPaths>,
    /// Host bind mounts, established while the host root is still reachable.
    pub volumes: &'a [BindMount],
    /// Explicit `--device` requests, installed after the private `/dev` tmpfs.
    pub devices: &'a [DeviceMount],
    /// O_PATH handles for rootless host devices opened before pivot_root.
    pub device_sources: &'a [Option<File>],
    /// O_PATH handles for explicit rootless `--device` sources.
    pub requested_device_sources: &'a [File],
    /// Detached clone of the host `/dev/shm` mount for `--ipc host`.
    pub host_shm: Option<RawFd>,
    /// Mount a private `/dev/shm` tmpfs. False for `--ipc none`, which keeps a
    /// private IPC namespace but deliberately leaves `/dev/shm` unmounted.
    pub mount_shm: bool,
    /// Requested private `/dev/shm` size in bytes; None keeps Docker's 64 MiB
    /// default. Ignored for `--ipc host` and `--ipc none`.
    pub shm_size: Option<u64>,
}

/// Full root migration + pseudo-filesystem assembly, run by the child inside the
/// new namespaces.
pub fn setup_rootfs(cfg: &RootfsConfig) -> ZResult<()> {
    trace::mark("child:mount:begin");

    // 1. Pin mount propagation: nothing mounted/unmounted later may propagate
    //    back to the host.
    syscalls::mount(Some(""), "/", None, MS_REC | MS_PRIVATE, None)?;
    trace::mark("child:mount:private-ok");

    // 1b. Optional OverlayFS / copy-up so container writes never touch `lower`.
    if let Some(ovl) = cfg.overlay {
        setup_overlay(cfg.rootless, ovl)?;
    }

    // 1c. Bind volumes while host paths are still reachable. Mounts created
    //     under the rootfs move with it through the recursive self-bind/pivot.
    mount_volumes(cfg.rootless, cfg.rootfs, cfg.volumes)?;
    trace::mark("child:mount:volumes-ok");

    // 2. The new root must itself be a mount point: recursive bind onto itself.
    let rootfs_str = cfg.rootfs.to_string_lossy().to_string();
    syscalls::mount(Some(&rootfs_str), &rootfs_str, None, MS_BIND | MS_REC, None)?;
    trace::mark("child:mount:bindself-ok");

    // 3. chdir into the new root.
    syscalls::chdir(cfg.rootfs)?;

    // 4. pivot_root(".", "."): the old root is stacked underneath the current dir.
    syscalls::pivot_root(".", ".")?;
    trace::mark("child:pivot-syscall-ok");

    // 5. Lazily detach the old root and chdir to the real "/".
    syscalls::umount2(".", MNT_DETACH)?;
    syscalls::chdir("/")?;
    trace::mark("child:pivot_root:done");

    mount_pseudo_fs(cfg.rootless, cfg.host_shm, cfg.mount_shm, cfg.shm_size)?;
    populate_dev(
        cfg.rootless,
        cfg.device_sources,
        cfg.devices,
        cfg.requested_device_sources,
    )?;
    apply_masked_and_readonly(cfg.rootless)?;

    if cfg.set_hostname {
        if let Some(h) = cfg.hostname {
            syscalls::sethostname(h)?;
        }
    }
    trace::mark("child:mount:done");
    Ok(())
}

/// Bind a host file or directory into the new root. The target path is checked
/// component-by-component so a malicious image cannot use a symlink to make a
/// bind land outside the rootfs.
fn mount_volumes(rootless: bool, rootfs: &Path, volumes: &[BindMount]) -> ZResult<()> {
    for volume in volumes {
        let target = safe_target(rootfs, &volume.target)?;
        if let Some(parent) = target.parent() {
            syscalls::mkdir_p(parent, 0o755)?;
        }
        let source = &volume.source;
        let meta = std::fs::metadata(source)
            .map_err(|e| crate::zerr!("stat volume source {}: {e}", source.display()))?;
        if meta.is_dir() {
            syscalls::mkdir_p(&target, 0o755)?;
        } else if !target.exists() {
            std::fs::write(&target, b"")
                .map_err(|e| crate::zerr!("create volume mount point {}: {e}", target.display()))?;
        }
        // Some hardened user namespaces reject recursive bind mounts; plain
        // binds cover the normal host directory/file volume case.
        let flags = if rootless { MS_BIND } else { MS_BIND | MS_REC };
        syscalls::mount(
            Some(&source.to_string_lossy()),
            target.to_string_lossy(),
            None,
            flags,
            None,
        )?;
        if volume.readonly {
            syscalls::mount(
                None,
                target.to_string_lossy(),
                None,
                MS_BIND | MS_REMOUNT | MS_RDONLY,
                None,
            )?;
        }
    }
    Ok(())
}

/// Convert an absolute container path to a safe path under `rootfs`.
pub(crate) fn safe_target(rootfs: &Path, target: &Path) -> ZResult<PathBuf> {
    let mut cur = rootfs.to_path_buf();
    for comp in target.components().skip(1) {
        match comp {
            std::path::Component::Normal(c) => {
                cur.push(c);
                if let Ok(md) = std::fs::symlink_metadata(&cur) {
                    if md.file_type().is_symlink() {
                        return Err(crate::zerr!(
                            "refusing mount target {}: intermediate symlink escapes the rootfs",
                            target.display()
                        ));
                    }
                }
            }
            _ => {
                return Err(crate::zerr!(
                    "invalid mount target {} (use an absolute path without '..')",
                    target.display()
                ))
            }
        }
    }
    Ok(cur)
}

/// Mount the per-container overlay (or copy the lower up as a fallback).
/// Runs in the child after MS_PRIVATE: the mount is private to the child's
/// namespace and disappears when the container exits.
fn setup_overlay(rootless: bool, ovl: &OverlayPaths) -> ZResult<()> {
    if ovl.tmpfs_upper {
        // Mount in the child so the parent's mount namespace keeps no reference;
        // it disappears with the container mount namespace.
        let dir = ovl
            .upper
            .parent()
            .ok_or_else(|| crate::zerr!("overlay upper has no parent"))?;
        syscalls::mount(
            Some("tmpfs"),
            dir.to_string_lossy(),
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV,
            Some("mode=0700"),
        )?;
        trace::mark("child:overlay:tmpfs-upper-ok");
        // The tmpfs hides the staging directories created by the parent.
        for path in [&ovl.upper, &ovl.work, &ovl.merged] {
            fsutil::mkdir_p(path)?;
        }
    }
    let data = format!(
        "lowerdir={},upperdir={},workdir={}",
        ovl.lower.display(),
        ovl.upper.display(),
        ovl.work.display()
    );
    let merged = ovl.merged.to_string_lossy().to_string();
    match syscalls::mount(
        Some("overlay"),
        &merged,
        Some("overlay"),
        0,
        Some(data.as_str()),
    ) {
        Ok(()) => {
            trace::mark("child:overlay:ok");
            Ok(())
        }
        Err(e) if rootless => {
            // Restricted rootless hosts may refuse overlay in a user namespace.
            // Fall back to a plain copy so writes are still isolated.
            eprintln!(
                "zerun: warn: overlay mount denied ({e}); copying lower into the per-run fs instead"
            );
            fsutil::copy_dir_all(&ovl.lower, &ovl.merged)?;
            trace::mark("child:overlay:copy-fallback");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Mount /proc, /dev, /dev/pts, /dev/shm, /dev/mqueue, /sys, cgroup2, /tmp.
///
/// rootful: any critical mount failure is an error. rootless: locked-down hosts
/// (or nested-container LSM policy) may refuse userns mounts of proc/sys; in that
/// case warn and continue, with `doctor` explaining the environment limit.
fn mount_pseudo_fs(
    rootless: bool,
    host_shm: Option<RawFd>,
    mount_shm: bool,
    shm_size: Option<u64>,
) -> ZResult<()> {
    let common = MS_NOSUID | MS_NOEXEC | MS_NODEV;

    // /proc is remounted in the container's mount namespace. Under the default
    // private PID namespace it shows only container processes; with --pid host
    // it intentionally exposes the host process list.
    syscalls::mkdir_p("/proc", 0o555)?;
    let proc_res = syscalls::mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        common | MS_RELATIME,
        None,
    );
    if proc_res.is_err() && !rootless {
        proc_res?; // rootful is strict
    } else if let Err(e) = proc_res {
        eprintln!("zerun: warn: /proc mount denied ({e}); rootless continues degraded, some /proc-dependent programs may misbehave");
    }

    // /dev: tmpfs + hand-made minimal device set (no devtmpfs, to avoid exposing
    // host devices).
    syscalls::mkdir_p("/dev", 0o755)?;
    require_or_warn(
        rootless,
        syscalls::mount(
            Some("tmpfs"),
            "/dev",
            Some("tmpfs"),
            MS_NOSUID | MS_STRICTATIME,
            Some("mode=755,size=65536k"),
        ),
        "/dev tmpfs",
    )?;
    syscalls::mkdir_p("/dev/pts", 0o620)?;
    require_or_warn(
        rootless,
        syscalls::mount(
            Some("devpts"),
            "/dev/pts",
            Some("devpts"),
            MS_NOSUID | MS_NOEXEC,
            Some("newinstance,ptmxmode=0666,mode=0620"),
        ),
        "/dev/pts",
    )?;
    syscalls::mkdir_p("/dev/shm", 0o1777)?;
    if !mount_shm {
        // Docker's --ipc none keeps a private SysV/POSIX IPC namespace but
        // deliberately does not provide the shared-memory mount.
    } else if let Some(source) = host_shm {
        require_or_warn(
            rootless,
            syscalls::move_mount(source, "/dev/shm"),
            "host /dev/shm for --ipc host",
        )?;
    } else {
        let data = shm_mount_data(shm_size);
        require_or_warn(
            rootless,
            syscalls::mount(
                Some("shm"),
                "/dev/shm",
                Some("tmpfs"),
                MS_NOSUID | MS_NODEV | MS_NOEXEC,
                Some(data.as_str()),
            ),
            "/dev/shm",
        )?;
    }
    syscalls::mkdir_p("/dev/mqueue", 0o755)?;
    require_or_warn(
        rootless,
        syscalls::mount(
            Some("mqueue"),
            "/dev/mqueue",
            Some("mqueue"),
            MS_NOSUID | MS_NODEV | MS_NOEXEC,
            None,
        ),
        "/dev/mqueue",
    )?;

    // /sys read-only. Inside a user namespace a direct sysfs mount may EPERM; fall
    // back to bind-mounting the host /sys read-only.
    syscalls::mkdir_p("/sys", 0o555)?;
    if syscalls::mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        common | MS_RDONLY,
        None,
    )
    .is_err()
        && syscalls::mount(
            Some("/sys"),
            "/sys",
            None,
            MS_BIND | MS_REC | MS_RDONLY,
            None,
        )
        .is_err()
    {
        // Both approaches failed (possible on old rootless kernels): not fatal,
        // leave the empty directory.
        eprintln!("zerun: warn: /sys not mounted (sysfs/bind both failed)");
    }

    // cgroup v2 mounted read-only so the container can see its own resource
    // accounting.
    syscalls::mkdir_p("/sys/fs/cgroup", 0o555)?;
    if syscalls::mount(
        Some("cgroup2"),
        "/sys/fs/cgroup",
        Some("cgroup2"),
        MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_RDONLY,
        None,
    )
    .is_err()
    {
        // Ignore when the host is not on a unified cgroup2 hierarchy (doctor reports it).
    }

    syscalls::mkdir_p("/tmp", 0o1777)?;
    require_or_warn(
        rootless,
        syscalls::mount(
            Some("tmp"),
            "/tmp",
            Some("tmpfs"),
            MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME,
            Some("mode=1777"),
        ),
        "/tmp tmpfs",
    )?;
    Ok(())
}

/// Kernel mount data for the private `/dev/shm` tmpfs. Docker's default is
/// 64 MiB; an explicit `--shm-size` overrides only this private mount and has
/// no effect when `/dev/shm` is absent (`--ipc none`) or host-shared.
fn shm_mount_data(size: Option<u64>) -> String {
    format!("mode=1777,size={}", size.unwrap_or(64 * 1024 * 1024))
}

/// rootful: mount failure is an error. rootless: warn and continue (degraded host).
fn require_or_warn(rootless: bool, r: ZResult<()>, what: &str) -> ZResult<()> {
    match r {
        Ok(()) => Ok(()),
        Err(e) if rootless => {
            eprintln!("zerun: warn: mount {what} denied ({e}); rootless continues degraded");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Minimal /dev device nodes and conventional symlinks.
/// rootful: mknod character devices; rootless (non-initial user ns): mknod is
/// restricted, so bind host whitelist devices instead.
/// Open host device handles before pivot_root hides the initial `/dev`.
///
/// Rootless containers cannot reliably create device nodes with `mknod`; the
/// handles are later exposed through `/proc/self/fd/*` after the private `/dev`
/// tmpfs is mounted. Missing or inaccessible devices are a degraded-host
/// warning, not a rootless setup failure.
pub fn open_rootless_device_sources(rootless: bool) -> Vec<Option<File>> {
    if !rootless {
        return Vec::new();
    }
    DEVICE_NODES
        .iter()
        .map(|(path, _, _)| match open_device_source(Path::new(path)) {
            Ok(source) => Some(source),
            Err(error) => {
                eprintln!("zerun: warn: cannot open rootless host device {path}: {error}");
                None
            }
        })
        .collect()
}

/// Open explicit rootless `--device` sources before pivot_root. Rootless
/// namespaces cannot recreate device nodes with `mknod`, so they bind the
/// original host inode through `/proc/self/fd` after the private `/dev` tmpfs
/// exists. Rootful launches recreate nodes from their major/minor pair instead.
pub fn open_requested_device_sources(
    rootless: bool,
    devices: &[DeviceMount],
) -> ZResult<Vec<File>> {
    if !rootless {
        return Ok(Vec::new());
    }
    devices
        .iter()
        .map(|device| {
            open_device_source(&device.source).map_err(|error| {
                crate::zerr!("open --device source {}: {error}", device.source.display())
            })
        })
        .collect()
}

/// Capture the host `/dev/shm` mount before pivot_root. `--ipc host` installs
/// this detached clone after the private `/dev` tmpfs so POSIX shared memory
/// remains shared with the host.
pub fn clone_host_shm_mount() -> ZResult<std::os::fd::OwnedFd> {
    syscalls::open_tree_clone("/dev/shm")
}

/// Minimal /dev device nodes and conventional symlinks.
/// rootful: mknod character devices; rootless (non-initial user ns): bind the
/// pre-opened host whitelist devices through procfs fd magic links.
fn populate_dev(
    rootless: bool,
    device_sources: &[Option<File>],
    devices: &[DeviceMount],
    requested_device_sources: &[File],
) -> ZResult<()> {
    for (index, &(path, maj, min)) in DEVICE_NODES.iter().enumerate() {
        if rootless {
            // Create an empty file on tmpfs as the mount point, then bind the
            // actual host device opened before pivot_root. Binding `path` to
            // itself here would only expose the empty mount-point file.
            if let Err(error) = std::fs::write(path, b"") {
                eprintln!("zerun: warn: cannot create rootless device mount point {path}: {error}");
                continue;
            }
            let Some(source) = device_sources.get(index).and_then(Option::as_ref) else {
                continue;
            };
            let source_path = format!("/proc/self/fd/{}", source.as_raw_fd());
            require_or_warn(
                true,
                syscalls::mount(Some(&source_path), path, None, MS_BIND, None),
                &format!("bind rootless device {path}"),
            )?;
        } else {
            // An explicit request for the same built-in node must be recreated
            // with the requested permission mode by the loop below.
            if devices.iter().any(|device| {
                device.target == Path::new(path)
                    && device_matches_numbers(device, DeviceKind::Char, maj, min)
            }) {
                continue;
            }
            syscalls::mknod_char(path, maj, min, 0o666)?;
        }
    }
    for (index, device) in devices.iter().enumerate() {
        let target = safe_target(Path::new("/"), &device.target)?;
        let existing = match std::fs::symlink_metadata(&target) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(crate::zerr!(
                    "inspect --device target {}: {error}",
                    device.target.display()
                ))
            }
        };
        if let Some(parent) = target.parent() {
            syscalls::mkdir_p(parent, 0o755)?;
        }

        if rootless {
            if let Some(metadata) = existing {
                if device_matches_metadata(device, &metadata) {
                    // A built-in device already provides this exact
                    // major/minor and the rootless path only supports full
                    // permissions, so the existing bind is equivalent.
                    continue;
                }
                return Err(crate::zerr!(
                    "--device target {} already exists",
                    device.target.display()
                ));
            }
            std::fs::write(&target, b"").map_err(|error| {
                crate::zerr!(
                    "create --device mount point {}: {error}",
                    device.target.display()
                )
            })?;
            let source = requested_device_sources.get(index).ok_or_else(|| {
                crate::zerr!(
                    "missing pre-opened source for --device {}",
                    device.target.display()
                )
            })?;
            let source_path = format!("/proc/self/fd/{}", source.as_raw_fd());
            syscalls::mount(
                Some(&source_path),
                target.to_string_lossy(),
                None,
                MS_BIND,
                None,
            )?;
        } else {
            if existing.is_some() {
                return Err(crate::zerr!(
                    "--device target {} already exists",
                    device.target.display()
                ));
            }
            let mode = device_node_mode(device.permissions);
            match device.kind {
                DeviceKind::Char => {
                    syscalls::mknod_char(&target, device.major, device.minor, mode)?
                }
                DeviceKind::Block => {
                    syscalls::mknod_block(&target, device.major, device.minor, mode)?
                }
            };
        }
    }
    let _ = syscalls::symlink("/proc/self/fd", "/dev/fd");
    let _ = syscalls::symlink("/proc/self/fd/0", "/dev/stdin");
    let _ = syscalls::symlink("/proc/self/fd/1", "/dev/stdout");
    let _ = syscalls::symlink("/proc/self/fd/2", "/dev/stderr");
    let _ = syscalls::symlink("/dev/pts/ptmx", "/dev/ptmx");
    Ok(())
}

fn device_matches_metadata(device: &DeviceMount, metadata: &std::fs::Metadata) -> bool {
    let file_type = metadata.file_type();
    let kind_matches = match device.kind {
        DeviceKind::Char => file_type.is_char_device(),
        DeviceKind::Block => file_type.is_block_device(),
    };
    kind_matches && device_numbers(metadata.rdev()) == (device.major, device.minor)
}

fn device_matches_numbers(device: &DeviceMount, kind: DeviceKind, major: u32, minor: u32) -> bool {
    device.kind == kind && device.major == major && device.minor == minor
}

fn device_node_mode(permissions: DevicePermissions) -> libc::mode_t {
    let mut mode = 0;
    if permissions.read {
        mode |= 0o444;
    }
    if permissions.write {
        mode |= 0o222;
    }
    mode
}

fn open_device_source(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)
}

fn apply_masked_and_readonly(rootless: bool) -> ZResult<()> {
    for p in MASKED_PATHS {
        let path = Path::new(p);
        if !path.exists() {
            continue;
        }
        // Mask regular proc files with /dev/null. Directory masks need a
        // private empty tmpfs; binding a character device over a directory
        // fails and would otherwise leave /sys/firmware visible.
        let result = if path.is_dir() {
            syscalls::mount(
                Some("tmpfs"),
                p,
                Some("tmpfs"),
                MS_NOSUID | MS_NODEV | MS_NOEXEC,
                Some("mode=000"),
            )
        } else {
            syscalls::mount(Some("/dev/null"), p, None, MS_BIND, None)
        };
        require_or_warn(rootless, result, &format!("mask {p}"))?;
    }
    for p in READONLY_PATHS {
        if Path::new(p).exists() {
            require_or_warn(
                rootless,
                syscalls::mount(Some(p), p, None, MS_BIND | MS_REC | MS_RDONLY, None),
                &format!("readonly {p}"),
            )?;
        }
    }
    Ok(())
}

/// Bind a host file into the container (internal /etc files and DNS setup).
#[allow(dead_code)]
pub fn bind_file_into(src_on_host: &Path, target_in_root: &str) -> ZResult<()> {
    let _ = src_on_host;
    let target = PathBuf::from(target_in_root);
    if let Some(parent) = target.parent() {
        syscalls::mkdir_p(parent, 0o755)?;
    }
    std::fs::write(&target, "").map_err(|_| last_err("create bind target"))?;
    syscalls::mount(
        Some(&src_on_host.to_string_lossy()),
        target_in_root,
        None,
        MS_BIND,
        None,
    )
}

#[cfg(test)]
mod bind_tests {
    #[test]
    fn rootless_device_source_inventory_matches_the_minimal_dev_set() {
        let sources = super::open_rootless_device_sources(true);
        assert_eq!(sources.len(), super::DEVICE_NODES.len());
    }

    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zerun-bind-{}-{name}", std::process::id()));
        fsutil::remove_dir_all_quiet(&dir);
        dir
    }

    #[test]
    fn private_shm_uses_docker_default_or_explicit_size() {
        assert_eq!(shm_mount_data(None), "mode=1777,size=67108864");
        assert_eq!(
            shm_mount_data(Some(96 * 1024 * 1024)),
            "mode=1777,size=100663296"
        );
    }

    #[test]
    fn parse_bind_accepts_files_and_modes() {
        let root = temp_path("parse");
        std::fs::create_dir_all(root.join("src")).unwrap();
        let host = std::fs::canonicalize(root.join("src")).unwrap();
        let bind = parse_bind(&format!("{}:/mnt/data:ro", host.display())).unwrap();
        assert_eq!(bind.source, host);
        assert_eq!(bind.target, PathBuf::from("/mnt/data"));
        assert!(bind.readonly);
        fsutil::remove_dir_all_quiet(&root);
    }

    #[test]
    fn parse_bind_rejects_ambiguous_or_unsafe_paths() {
        assert!(parse_bind("data:/mnt").is_ok());
        assert!(parse_bind("/tmp:mnt").is_err());
        assert!(parse_bind("/tmp:/../etc").is_err());
        assert!(parse_bind("/tmp:/tmp:ro:extra").is_err());
        assert!(parse_bind("/tmp:/tmp:bad").is_err());
    }

    #[test]
    fn parse_bind_accepts_named_volumes_without_touching_storage() {
        let bind = parse_bind("app-data:/var/lib/app:ro").unwrap();
        assert!(bind.source.as_os_str().is_empty());
        assert_eq!(bind.named.as_deref(), Some("app-data"));
        assert_eq!(bind.target, PathBuf::from("/var/lib/app"));
        assert!(bind.readonly);
        assert_eq!(bind.raw, "app-data:/var/lib/app:ro");
        assert!(validate_volume_name("app_data.v2").is_ok());
        assert!(validate_volume_name("..").is_err());
        assert!(validate_volume_name("bad/name").is_err());
    }

    #[test]
    fn safe_target_rejects_symlinked_tmpfs_paths() {
        let root = temp_path("safe-target");
        let outside = temp_path("safe-target-outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("redirect")).unwrap();

        assert!(safe_target(&root, Path::new("/redirect/file")).is_err());
        assert_eq!(
            safe_target(&root, Path::new("/new/file")).unwrap(),
            root.join("new/file")
        );
        fsutil::remove_dir_all_quiet(&root);
        fsutil::remove_dir_all_quiet(&outside);
    }

    #[test]
    fn parse_tmpfs_accepts_paths_and_options() {
        let plain = parse_tmpfs("/scratch").unwrap();
        assert_eq!(plain.target, PathBuf::from("/scratch"));
        assert!(plain.data.is_empty());
        assert!(!plain.readonly);
        assert_eq!(plain.raw, "/scratch");

        let sized = parse_tmpfs("/scratch:size=16m,mode=0700,ro").unwrap();
        assert_eq!(sized.target, PathBuf::from("/scratch"));
        assert_eq!(sized.data, "size=16777216,mode=700");
        assert!(sized.readonly);
        assert_eq!(sized.raw, "/scratch:size=16m,mode=0700,ro");

        let rw = parse_tmpfs("/tmp:size=64M,ro,rw").unwrap();
        assert!(!rw.readonly);
    }

    #[test]
    fn parse_tmpfs_rejects_unsafe_or_unknown_options() {
        assert!(parse_tmpfs("scratch").is_err());
        assert!(parse_tmpfs("/a/../b").is_err());
        assert!(parse_tmpfs("/").is_err());
        assert!(parse_tmpfs("/x:size=abc").is_err());
        assert_eq!(parse_tmpfs("/x:size=64m").unwrap().data, "size=67108864");
        assert_eq!(parse_tmpfs("/x:size=64").unwrap().data, "size=64");
        assert_eq!(parse_tmpfs("/x:size=1.5G").unwrap().data, "size=1610612736");
        assert_eq!(parse_tmpfs("/x:size=1MB").unwrap().data, "size=1048576");
        assert!(parse_tmpfs("/x:mode=99").is_err());
        assert!(parse_tmpfs("/x:mode=8888").is_err());
        assert!(parse_tmpfs("/x:nosuid").is_err());
        assert!(parse_tmpfs("/x:size=1m:extra").is_err());
    }

    #[test]
    fn parse_mount_accepts_bind_volume_and_tmpfs_requests() {
        let root = temp_path("parse-mount");
        std::fs::create_dir_all(root.join("src")).unwrap();
        let host = std::fs::canonicalize(root.join("src")).unwrap();

        let bind = parse_mount(&format!(
            "type=bind,source={},target=/mnt/data,readonly",
            host.display()
        ))
        .unwrap();
        let MountRequest::Bind(bind) = bind else {
            panic!("expected a bind mount");
        };
        assert_eq!(bind.source, host);
        assert_eq!(bind.target, PathBuf::from("/mnt/data"));
        assert!(bind.named.is_none());
        assert!(bind.readonly);
        assert_eq!(bind.raw, format!("{}:/mnt/data:ro", host.display()));

        let volume = parse_mount("type=volume,src=app-data,dst=/var/lib/app,rw").unwrap();
        let MountRequest::Bind(volume) = volume else {
            panic!("expected a volume mount");
        };
        assert!(volume.source.as_os_str().is_empty());
        assert_eq!(volume.named.as_deref(), Some("app-data"));
        assert_eq!(volume.target, PathBuf::from("/var/lib/app"));
        assert!(!volume.readonly);
        assert_eq!(volume.raw, "app-data:/var/lib/app:rw");

        let tmpfs =
            parse_mount("type=tmpfs,destination=/scratch,tmpfs-size=16m,tmpfs-mode=0700,readonly")
                .unwrap();
        let MountRequest::Tmpfs(tmpfs) = tmpfs else {
            panic!("expected a tmpfs mount");
        };
        assert_eq!(tmpfs.target, PathBuf::from("/scratch"));
        assert_eq!(tmpfs.data, "size=16777216,mode=700");
        assert!(tmpfs.readonly);
        assert_eq!(tmpfs.raw, "/scratch:ro,size=16777216,mode=700");

        fsutil::remove_dir_all_quiet(&root);
    }

    #[test]
    fn parse_mount_rejects_ambiguous_or_invalid_requests() {
        for value in [
            "",
            "source=/tmp,target=/mnt",
            "type=bind,source=/tmp",
            "type=bind,source=relative,target=/mnt",
            "type=bind,source=/tmp,target=relative",
            "type=bind,source=/tmp,target=/../mnt",
            "type=bind,source=/tmp,target=/mnt,tmpfs-size=1m",
            "type=bind,source=/tmp,target=/mnt,readonly=1",
            "type=bind,source=/tmp,target=/mnt,ro=false",
            "type=volume,source=/tmp,target=/mnt",
            "type=volume,source=app-data",
            "type=tmpfs,source=app-data,target=/scratch",
            "type=tmpfs,target=/scratch,tmpfs-size=bad",
            "type=tmpfs,target=/scratch,tmpfs-mode=8888",
            "type=tmpfs,target=/scratch,unknown=true",
            "type=bind,type=volume,source=app-data,target=/mnt",
            "type=bind,source=/tmp,target=/mnt,",
            "type=overlay,source=/tmp,target=/mnt",
        ] {
            assert!(parse_mount(value).is_err(), "{value:?} should be rejected");
        }
    }

    #[test]
    fn parse_device_accepts_docker_forms() {
        let device = parse_device("/dev/null:/dev/zerun-null:rw").unwrap();
        assert_eq!(device.source, PathBuf::from("/dev/null"));
        assert_eq!(device.target, PathBuf::from("/dev/zerun-null"));
        assert_eq!(device.kind, DeviceKind::Char);
        assert_eq!((device.major, device.minor), (1, 3));
        assert!(device.permissions.read);
        assert!(device.permissions.write);
        assert!(!device.permissions.mknod);
        assert_eq!(device.raw, "/dev/null:/dev/zerun-null:rw");

        let default_target = parse_device("/dev/null").unwrap();
        assert_eq!(default_target.target, PathBuf::from("/dev/null"));
        assert!(default_target.permissions.is_full());

        let explicit_target = parse_device("/dev/null:/dev/fuse").unwrap();
        assert_eq!(explicit_target.target, PathBuf::from("/dev/fuse"));
        assert!(explicit_target.permissions.is_full());

        let explicit_permissions = parse_device("/dev/null:r").unwrap();
        assert_eq!(explicit_permissions.target, PathBuf::from("/dev/null"));
        assert!(explicit_permissions.permissions.read);
        assert!(!explicit_permissions.permissions.write);
        assert!(!explicit_permissions.permissions.mknod);
    }

    #[test]
    fn parse_device_rejects_non_devices_and_bad_permissions() {
        for value in [
            "",
            "dev/null",
            "/dev/null:/dev/zerun-null:",
            "/dev/null:/dev/zerun-null:rx",
            "/dev/null:/dev/zerun-null:rr",
            "/dev/null:relative",
            "/dev/null:/../zerun-null:rw",
            "/dev/null:/dev/a:/dev/b:rwm",
            "/tmp",
            "/dev",
        ] {
            assert!(parse_device(value).is_err(), "{value:?} should be rejected");
        }
    }

    #[test]
    fn device_node_mode_reflects_read_and_write_permissions() {
        let mode = |value: &str| {
            device_node_mode(
                parse_device(&format!("/dev/null:{value}"))
                    .unwrap()
                    .permissions,
            )
        };
        assert_eq!(mode("rwm"), 0o666);
        assert_eq!(mode("rw"), 0o666);
        assert_eq!(mode("r"), 0o444);
        assert_eq!(mode("w"), 0o222);
        assert_eq!(mode("m"), 0o000);
    }

    #[test]
    fn device_numbers_decode_large_minors() {
        for (major, minor) in [(8, 0), (8, 300), (12, 1_048_575)] {
            assert_eq!(device_numbers(libc::makedev(major, minor)), (major, minor));
        }
    }

    #[test]
    fn device_validation_rejects_rootless_subsets_and_duplicate_targets() {
        let restricted = parse_device("/dev/null:/dev/zerun-null:r").unwrap();
        assert!(validate_device_permissions(true, std::slice::from_ref(&restricted)).is_err());
        assert!(validate_device_permissions(false, &[restricted]).is_ok());

        let first = parse_device("/dev/null:/dev/zerun-null:rwm").unwrap();
        let duplicate = parse_device("/dev/zero:/dev/zerun-null:rwm").unwrap();
        assert!(validate_device_targets(&[first, duplicate]).is_err());
    }
}
