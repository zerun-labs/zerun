//! Isolation orchestration.
//!
//! Parent: create cgroup -> clone the child -> write cgroup.procs -> forward
//! signals -> wait. Child: mount/pivot -> pseudo-fs -> security hardening ->
//! execve (or run the built-in mini-init first).
use crate::cgroup::{CgroupV2, ResourceLimits};
use crate::error::ZResult;
use crate::mounts::{setup_rootfs, RootfsConfig};
use crate::seccomp::SeccompMode;
use crate::security;
use crate::syscalls;
use crate::trace;
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, Ordering};

#[derive(Debug, Clone, Default)]
pub enum NetMode {
    /// Fresh netns with loopback only (bridge/veth arrives with the networking
    /// milestone).
    #[default]
    None,
    /// Share the host network (a single-process unshare path would be possible
    /// here, but M1 still goes through clone for uniformity).
    Host,
}

#[derive(Debug, Clone)]
pub struct RunSpec {
    pub rootfs: PathBuf,
    pub argv: Vec<String>,
    pub hostname: Option<String>,
    pub net: NetMode,
    pub use_init: bool,
    pub limits: ResourceLimits,
    pub seccomp: SeccompMode,
    pub id: String,
}

static TARGET_CHILD: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward_to_child(sig: libc::c_int) {
    let pid = TARGET_CHILD.load(Ordering::Relaxed);
    if pid > 0 {
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

/// Full run path. Returns the workload exit code.
pub fn run_container(spec: RunSpec) -> ZResult<i32> {
    trace::init();
    trace::mark("parent:begin");

    // Create the cgroup on the parent side first (attach right after clone).
    // Skipped when no limits are set (typical rootless without delegation).
    let has_limits =
        spec.limits.memory.is_some() || spec.limits.cpus.is_some() || spec.limits.pids.is_some();
    let cg = if has_limits {
        Some(CgroupV2::create(&spec.id, &spec.limits)?)
    } else {
        None
    };

    let (err_r, err_w) = syscalls::pipe2_cloexec()?;

    // clone flags: PID/MNT/UTS/IPC/CGROUP on by default; NEWNET additionally for
    // --net none. Non-root automatically adds NEWUSER (the kernel guarantees the
    // user namespace is created first).
    let rootless = unsafe { libc::geteuid() } != 0;
    let mut flags = libc::CLONE_NEWPID
        | libc::CLONE_NEWNS
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWCGROUP
        | libc::SIGCHLD;
    if matches!(spec.net, NetMode::None) {
        flags |= libc::CLONE_NEWNET;
    }
    if rootless {
        flags |= libc::CLONE_NEWUSER;
    }
    // The host euid/egid must be captured before clone: once the child is inside
    // the new user namespace and before the mapping is written, geteuid() reports
    // 65534 (nobody).
    let host_euid = unsafe { libc::geteuid() };
    let host_egid = unsafe { libc::getegid() };

    let child_spec = spec.clone();
    let pid = syscalls::clone_into(flags, move || {
        child_main(child_spec, err_w, err_r, rootless, host_euid, host_egid)
    })?;
    trace::mark("parent:clone:done");

    // The parent keeps neither the write end nor the child end of the pipe.
    syscalls::close(err_w);
    TARGET_CHILD.store(pid, Ordering::Relaxed);

    // Write cgroup.procs (the child may already have exited; attach ignores ESRCH).
    if let Some(cg) = &cg {
        cg.attach(pid)?;
    }

    // Forward terminal signals to the container PID 1.
    install_forward(libc::SIGINT);
    install_forward(libc::SIGTERM);
    install_forward(libc::SIGHUP);

    // Block on the error pipe: EOF means the child successfully exec'd
    // (CLOEXEC closes the write end).
    let mut buf = [0u8; 2048];
    let n = read_all(err_r, &mut buf)?;
    syscalls::close(err_r);
    if n > 0 {
        // The child failed before exec.
        let msg = String::from_utf8_lossy(&buf[..n]);
        eprintln!("zerun: container setup failed: {msg}");
        let _ = wait_pid(pid);
        if let Some(cg) = cg {
            cg.cleanup();
        }
        return Ok(1);
    }
    trace::mark("parent:child-execved");

    let code = wait_pid(pid)?;
    if let Some(cg) = cg {
        cg.cleanup();
    }
    trace::mark("parent:end");
    Ok(code)
}

fn child_main(
    spec: RunSpec,
    err_w: RawFd,
    err_r: RawFd,
    rootless: bool,
    host_euid: u32,
    host_egid: u32,
) -> ZResult<()> {
    syscalls::close(err_r);

    // Report any failure to the parent over the pipe; the trampoline then exits 1.
    let result = child_stage(&spec, rootless, host_euid, host_egid, err_w);
    if let Err(e) = result {
        let msg = format!("{e}");
        syscalls::write_fd(err_w, msg.as_bytes());
        syscalls::close(err_w);
        return Err(e);
    }
    Ok(())
}

fn child_stage(
    spec: &RunSpec,
    rootless: bool,
    host_euid: u32,
    host_egid: u32,
    err_w: RawFd,
) -> ZResult<()> {
    // 0. rootless: write the uid/gid mapping before doing any mounts.
    if rootless {
        write_self_id_mapping(host_euid, host_egid)?;
        if std::env::var_os("ZERUN_DEBUG").is_some() {
            let st = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
            for l in st.lines().filter(|l| l.starts_with("Cap")) {
                eprintln!("[debug] {l}");
            }
        }
    }

    // 1. Root migration + pseudo-filesystems.
    let cfg = RootfsConfig {
        rootfs: &spec.rootfs,
        hostname: spec.hostname.as_deref(),
        rootless,
    };
    setup_rootfs(&cfg)?;

    // 2. With --net none, bring loopback up so 127.0.0.1 works.
    if matches!(spec.net, NetMode::None) {
        syscalls::bring_loopback_up()?;
    }

    // 3. Security hardening: no_new_privs -> capability drop -> seccomp profile.
    security::harden(spec.seccomp)?;

    // 4. Start the workload.
    //    --init: do NOT re-exec our own binary (that would depend on
    //    /proc/self/exe being visible under the new root). Instead the container
    //    PID 1 directly runs the mini-init logic: it forks the workload (PID 2),
    //    reaps orphans, forwards signals, and _exit()s with the workload code.
    //    Setup has succeeded at this point, so close the error-pipe write end
    //    explicitly so the parent's blocking read gets EOF.
    //    (The direct-exec path relies on O_CLOEXEC; the --init path never execs,
    //    so it must close the write end manually, otherwise the parent would block
    //    forever on the sync read.)
    syscalls::close(err_w);
    trace::mark("child:exec:begin");
    if spec.use_init {
        let code = crate::mini_init::run(&spec.argv)?;
        unsafe { libc::_exit(code) };
    }

    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(&spec.argv[0]);
    cmd.args(spec.argv.iter().skip(1));

    // Environment: inherit the parent env, then override with container defaults
    // (from the image config.Env once the image engine lands).
    cmd.env(
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    )
    .env("HOME", "/root")
    .env(
        "HOSTNAME",
        spec.hostname.clone().unwrap_or_else(|| spec.id.clone()),
    );

    let err = cmd.exec(); // only returns on failure
    Err(crate::zerr!("execve failed: {err}"))
}

/// Unprivileged rootless: map uid/gid 0 inside the new user namespace to the host
/// euid/egid (single mapping; values captured by the parent before clone).
/// setgroups must be denied before gid_map can be written.
fn write_self_id_mapping(host_euid: u32, host_egid: u32) -> ZResult<()> {
    // Ignore setgroups write failures (some kernels deny it by default already).
    let _ = std::fs::write("/proc/self/setgroups", "deny");
    std::fs::write("/proc/self/uid_map", format!("0 {host_euid} 1"))
        .map_err(|e| crate::zerr!("write uid_map failed: {e}"))?;
    std::fs::write("/proc/self/gid_map", format!("0 {host_egid} 1"))
        .map_err(|e| crate::zerr!("write gid_map failed: {e}"))?;
    Ok(())
}

fn install_forward(sig: libc::c_int) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = forward_to_child as extern "C" fn(libc::c_int) as usize;
        libc::sigemptyset(&mut sa.sa_mask as *mut libc::sigset_t);
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

fn read_all(fd: RawFd, buf: &mut [u8]) -> ZResult<usize> {
    let mut total = 0;
    loop {
        let n = syscalls::read_fd(fd, &mut buf[total..])?; // EINTR is retried in syscalls.rs
        if n == 0 {
            return Ok(total); // EOF: the child successfully entered the workload
        }
        total += n as usize;
        if total == buf.len() {
            return Ok(total);
        }
    }
}

fn wait_pid(pid: i32) -> ZResult<i32> {
    loop {
        let mut status: libc::c_int = 0;
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e.into());
        }
        if libc::WIFEXITED(status) {
            return Ok(libc::WEXITSTATUS(status));
        }
        if libc::WIFSIGNALED(status) {
            return Ok(128 + libc::WTERMSIG(status));
        }
    }
}
