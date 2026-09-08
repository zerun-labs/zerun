//! Root migration and pseudo-filesystem setup (child side).
//!
//! Current stage: pivot_root sequence over an already-unpacked rootfs directory.
//! OverlayFS layering of multiple lower dirs lands in M2.
use crate::error::{last_err, ZResult};
use crate::syscalls;
use crate::trace;
use libc::{
    MNT_DETACH, MS_BIND, MS_NODEV, MS_NOEXEC, MS_NOSUID, MS_PRIVATE, MS_RDONLY, MS_REC,
    MS_RELATIME, MS_STRICTATIME,
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

pub struct RootfsConfig<'a> {
    pub rootfs: &'a Path,
    pub hostname: Option<&'a str>,
    /// rootless (NEWUSER) cannot mknod; bind-mount whitelisted host devices instead.
    pub rootless: bool,
}

/// Full root migration + pseudo-filesystem assembly, run by the child inside the
/// new namespaces.
pub fn setup_rootfs(cfg: &RootfsConfig) -> ZResult<()> {
    trace::mark("child:mount:begin");

    // 1. Pin mount propagation: nothing mounted/unmounted later may propagate
    //    back to the host.
    syscalls::mount(Some(""), "/", None, MS_REC | MS_PRIVATE, None)?;
    trace::mark("child:mount:private-ok");

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

/// Bind a host file into the container (currently only simple binds such as
/// resolv.conf/hosts; volumes arrive in a later milestone).
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
