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
    if !container.starts_with('/') {
        return Err(format!("-v: container path '{container}' must be absolute"));
    }
    if container == "/" {
        return Err("-v: refusing to mount over the container root".to_string());
    }
    if !Path::new(container)
        .components()
        .skip(1)
        .all(|component| matches!(component, std::path::Component::Normal(_)))
    {
        return Err(format!(
            "-v: container path '{container}' must be absolute without '.' or '..'"
        ));
    }

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

/// Parse Docker-style `--tmpfs PATH[:opts]`. Options are comma-separated
/// `key=value` pairs; `size` accepts K/M/G suffixes and `mode` an octal value.
/// Anything else is rejected so a typo fails loudly instead of silently
/// mounting a tmpfs the operator did not ask for.
pub fn parse_tmpfs(value: &str) -> Result<TmpfsMount, String> {
    let (path, opts) = match value.split_once(':') {
        Some((p, o)) if !o.is_empty() => (p, Some(o)),
        _ => (value, None),
    };
    if !path.starts_with('/') {
        return Err(format!("--tmpfs: container path '{path}' must be absolute"));
    }
    if !Path::new(path)
        .components()
        .skip(1)
        .all(|component| matches!(component, std::path::Component::Normal(_)))
    {
        return Err(format!(
            "--tmpfs: container path '{path}' must be absolute without '.' or '..'"
        ));
    }
    if path == "/" {
        return Err("--tmpfs: refusing to mount over the container root".to_string());
    }

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
                    if !valid_size_suffix(val) {
                        return Err(format!(
                            "--tmpfs: invalid size '{val}' (K/M/G suffix required)"
                        ));
                    }
                    push_opt(&mut data, "size", val);
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

fn valid_size_suffix(v: &str) -> bool {
    let digits = v
        .strip_suffix(|c: char| matches!(c, 'k' | 'K' | 'm' | 'M' | 'g' | 'G'))
        .unwrap_or(v);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
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
        syscalls::mkdir_p(&m.target, 0o1777)?;
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
                m.target.to_string_lossy(),
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
    /// rootless (NEWUSER) cannot mknod; bind-mount whitelisted host devices instead.
    pub rootless: bool,
    /// When set, first make `rootfs` a writable overlay whose lower is read-only.
    pub overlay: Option<&'a OverlayPaths>,
    /// Host bind mounts, established while the host root is still reachable.
    pub volumes: &'a [BindMount],
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

    mount_pseudo_fs(cfg.rootless)?;
    populate_dev(cfg.rootless)?;
    apply_masked_and_readonly()?;

    if let Some(h) = cfg.hostname {
        syscalls::sethostname(h)?;
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
fn safe_target(rootfs: &Path, target: &Path) -> ZResult<PathBuf> {
    let mut cur = rootfs.to_path_buf();
    for comp in target.components().skip(1) {
        match comp {
            std::path::Component::Normal(c) => {
                cur.push(c);
                if let Ok(md) = std::fs::symlink_metadata(&cur) {
                    if md.file_type().is_symlink() {
                        return Err(crate::zerr!(
                            "refusing volume target {}: intermediate symlink escapes the rootfs",
                            target.display()
                        ));
                    }
                }
            }
            _ => {
                return Err(crate::zerr!(
                    "invalid volume target {} (use an absolute path without '..')",
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
fn mount_pseudo_fs(rootless: bool) -> ZResult<()> {
    let common = MS_NOSUID | MS_NOEXEC | MS_NODEV;

    // /proc must be mounted inside the new PID namespace, otherwise the container
    // would see the host process list.
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
    require_or_warn(
        rootless,
        syscalls::mount(
            Some("shm"),
            "/dev/shm",
            Some("tmpfs"),
            MS_NOSUID | MS_NODEV | MS_NOEXEC,
            Some("mode=1777,size=65536k"),
        ),
        "/dev/shm",
    )?;
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
fn populate_dev(rootless: bool) -> ZResult<()> {
    const NODES: &[(&str, u32, u32)] = &[
        ("/dev/null", 1, 3),
        ("/dev/zero", 1, 5),
        ("/dev/full", 1, 7),
        ("/dev/random", 1, 8),
        ("/dev/urandom", 1, 9),
        ("/dev/tty", 5, 0),
    ];
    for &(path, maj, min) in NODES {
        if rootless {
            // Create an empty file on tmpfs as the mount point, then bind the host
            // device with the same name.
            if std::fs::write(path, b"").is_ok() {
                let _ = syscalls::mount(Some(path), path, None, MS_BIND, None);
            }
        } else {
            syscalls::mknod_char(path, maj, min, 0o666)?;
        }
    }

    let _ = syscalls::symlink("/proc/self/fd", "/dev/fd");
    let _ = syscalls::symlink("/proc/self/fd/0", "/dev/stdin");
    let _ = syscalls::symlink("/proc/self/fd/1", "/dev/stdout");
    let _ = syscalls::symlink("/proc/self/fd/2", "/dev/stderr");
    let _ = syscalls::symlink("/dev/pts/ptmx", "/dev/ptmx");
    Ok(())
}

fn apply_masked_and_readonly() -> ZResult<()> {
    for p in MASKED_PATHS {
        if Path::new(p).exists() {
            // Bind /dev/null over the sensitive path to mask it; skip if absent.
            let _ = syscalls::mount(Some("/dev/null"), p, None, MS_BIND, None);
        }
    }
    for p in READONLY_PATHS {
        if Path::new(p).exists() {
            let _ = syscalls::mount(Some(p), p, None, MS_BIND | MS_REC | MS_RDONLY, None);
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
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zerun-bind-{}-{name}", std::process::id()));
        fsutil::remove_dir_all_quiet(&dir);
        dir
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
    fn parse_tmpfs_accepts_paths_and_options() {
        let plain = parse_tmpfs("/scratch").unwrap();
        assert_eq!(plain.target, PathBuf::from("/scratch"));
        assert!(plain.data.is_empty());
        assert!(!plain.readonly);
        assert_eq!(plain.raw, "/scratch");

        let sized = parse_tmpfs("/scratch:size=16m,mode=0700,ro").unwrap();
        assert_eq!(sized.target, PathBuf::from("/scratch"));
        assert_eq!(sized.data, "size=16m,mode=700");
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
        assert_eq!(parse_tmpfs("/x:size=64m").unwrap().data, "size=64m");
        assert_eq!(parse_tmpfs("/x:size=64").unwrap().data, "size=64");
        assert!(parse_tmpfs("/x:mode=99").is_err());
        assert!(parse_tmpfs("/x:mode=8888").is_err());
        assert!(parse_tmpfs("/x:nosuid").is_err());
        assert!(parse_tmpfs("/x:size=1m:extra").is_err());
    }
}
