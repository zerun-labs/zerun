//! `zerun exec` — join a running container and run a command inside it.
//!
//! Model (in-process; no re-exec needed):
//!
//!   * the CLI forks a joiner (C);
//!   * C opens every `/proc/<pid>/ns/*` fd of the container's PID 1 **in the
//!     host context** and keeps the `File`s alive, then setns()es into the
//!     container's namespaces — the private `user` namespace first (only
//!     rootless containers have one), then mnt/uts/ipc/net/cgroup;
//!   * C then setns(pid): a process cannot change its own PID namespace, but
//!     every child born *after* that call is a member of the container's PID
//!     namespace, so C forks the worker (D) next;
//!   * D joins the container's cgroup (best effort), applies the same
//!     no_new_privs -> caps -> seccomp hardening as the container, chdir()s to
//!     the container working directory and execve()s the requested command.
//!
//! Joining the mount namespace means D shares the container's live rootfs and
//! its /proc /dev /sys mounts — exactly what `docker exec` shows. D is born as
//! a child of the container's PID 1 from the namespace's point of view (its
//! real parent C lives outside and reaps it through the host PID), so it is
//! reaped like any other container process.
use crate::error::ZResult;
use crate::state::{ContainerState, Status};
use crate::workload;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;

/// Join the running container described by `state` and run `argv` with the
/// container environment. Returns the command's exit code.
pub fn run(
    state: &ContainerState,
    env_extra: &[String],
    workdir: Option<&str>,
    argv: &[String],
) -> ZResult<i32> {
    if state.status != Status::Running {
        return Err(crate::zerr!(
            "container {} is not running (status {})",
            state.id,
            state.status_label()
        ));
    }
    let pid = state
        .pid
        .filter(|p| *p > 0)
        .ok_or_else(|| crate::zerr!("container {} has no live PID", state.id))?;
    if !state.pid_alive() {
        return Err(crate::zerr!(
            "container {} is not running (PID {pid} is gone)",
            state.id
        ));
    }
    if argv.is_empty() {
        return Err(crate::zerr!("exec: a command is required"));
    }

    // The joiner C.
    match unsafe { libc::fork() } {
        -1 => Err(crate::zerr!(
            "exec: fork: {}",
            std::io::Error::last_os_error()
        )),
        0 => {
            let code = joiner(state, pid, env_extra, workdir, argv);
            unsafe { libc::_exit(code) }
        }
        parent => {
            // Wait for C, which exits with D's code.
            let mut status: libc::c_int = 0;
            loop {
                let r = unsafe { libc::waitpid(parent, &mut status, 0) };
                if r < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(e.into());
                }
                break;
            }
            if libc::WIFEXITED(status) {
                Ok(libc::WEXITSTATUS(status))
            } else if libc::WIFSIGNALED(status) {
                Ok(128 + libc::WTERMSIG(status))
            } else {
                Ok(1)
            }
        }
    }
}

/// Which namespaces `exec` joins, and the order they must be entered in.
/// Rootless containers have a private `user` namespace that owns the others:
/// setns() into them is only permitted from inside it, so `user` must come
/// first. Rootful containers share the initial user namespace (setns into it
/// fails with EINVAL), so it is skipped entirely. `pid` is joined last and
/// never takes effect on C itself, only on its children.
fn joiner(
    state: &ContainerState,
    container_pid: i32,
    env_extra: &[String],
    workdir: Option<&str>,
    argv: &[String],
) -> i32 {
    // Open every namespace fd while we are still in the host context: after
    // setns(mnt) the container's /proc replaces ours and host paths vanish.
    // The File objects must stay alive (and therefore open) until the last
    // setns call, hence the explicit vector — dropping them early would close
    // the fd and make the stored RawFd stale.
    let mut order: Vec<&str> = Vec::with_capacity(7);
    if state.rootless {
        order.push("user");
    }
    order.extend(["mnt", "uts", "ipc", "net", "cgroup", "pid"]);
    let mut ns: Vec<(File, &str)> = Vec::with_capacity(order.len());
    for name in order {
        let path = format!("/proc/{container_pid}/ns/{name}");
        match File::open(&path) {
            Ok(f) => ns.push((f, name)),
            Err(e) => {
                eprintln!("zerun exec: open {path}: {e}");
                return 1;
            }
        }
    }

    for (f, name) in ns.iter() {
        if *name == "pid" {
            continue; // handled below, right before the second fork
        }
        if let Err(e) = setns(f, name) {
            eprintln!("zerun exec: {e}");
            return 1;
        }
    }
    for (f, name) in ns.iter() {
        if *name == "pid" {
            if let Err(e) = setns(f, name) {
                eprintln!("zerun exec: {e}");
                return 1;
            }
            break;
        }
    }
    // ns (the File owners) is dropped here, after every setns call. From this
    // point on all future children are members of the container's PID ns.

    // Second fork: D is born inside the container's PID namespace.
    match unsafe { libc::fork() } {
        -1 => {
            eprintln!("zerun exec: fork: {}", std::io::Error::last_os_error());
            1
        }
        0 => {
            let code = worker(state, env_extra, workdir, argv);
            unsafe { libc::_exit(code) }
        }
        d => {
            // C waits for D and mirrors its exit code to the CLI.
            let mut status: libc::c_int = 0;
            loop {
                let r = unsafe { libc::waitpid(d, &mut status, 0) };
                if r < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    eprintln!("zerun exec: waitpid: {e}");
                    return 1;
                }
                break;
            }
            if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else if libc::WIFSIGNALED(status) {
                128 + libc::WTERMSIG(status)
            } else {
                1
            }
        }
    }
}

/// setns into one namespace by fd, with a readable error.
fn setns(f: &File, what: &str) -> Result<(), String> {
    let rc = unsafe { libc::setns(f.as_raw_fd(), 0) };
    if rc != 0 {
        return Err(format!(
            "setns({what}): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// The in-container worker: cgroup join, cwd, env, hardening, exec.
fn worker(
    state: &ContainerState,
    env_extra: &[String],
    workdir: Option<&str>,
    argv: &[String],
) -> i32 {
    // Best effort: join the container's cgroup so the exec'd process is
    // accounted against the same memory/cpu/pids limits.
    if let Some(cg) = &state.cgroup {
        let procs = Path::new(cg).join("cgroup.procs");
        let _ = std::fs::write(&procs, std::process::id().to_string());
    }

    // Working directory: `-w` wins, then the container's recorded cwd, then
    // the container root (the image default when no WorkingDir is configured).
    let cwd = workdir
        .map(str::to_string)
        .or_else(|| state.cwd.clone())
        .unwrap_or_else(|| "/".to_string());
    if let Err(e) = std::env::set_current_dir(&cwd) {
        eprintln!("zerun exec: chdir {cwd}: {e}");
        return 1;
    }

    // Environment: the container's recorded env (image mode) or the caller's
    // inherited env (legacy rootfs mode), plus `-e` overrides.
    let mut pairs: Vec<(String, String)> = Vec::new();
    if state.env.is_empty() {
        pairs.extend(std::env::vars());
    } else {
        for kv in &state.env {
            if let Some((k, v)) = kv.split_once('=') {
                pairs.push((k.to_string(), v.to_string()));
            }
        }
    }
    for kv in env_extra {
        match kv.split_once('=') {
            Some((k, v)) => upsert(&mut pairs, k, v),
            None => {
                // `-e NAME` passes the host value through (docker semantics).
                if let Ok(v) = std::env::var(kv) {
                    upsert(&mut pairs, kv, &v);
                }
            }
        }
    }

    // Resolve a bare argv[0] against the container PATH; entries already
    // containing '/' are used as-is. The resolved absolute path is passed to
    // exec directly, so PATH lookup never depends on the exec-time environ.
    let mut resolved = argv.to_vec();
    if let Some(first) = resolved.first_mut() {
        *first = workload::resolve_argv0(first, &pairs);
    }

    if let Err(e) = crate::security::harden(crate::seccomp::SeccompMode::Default) {
        eprintln!("zerun exec: {e}");
        return 1;
    }

    // Drop to the container's configured user (same sequence as `run`), so
    // exec'd commands see the image/container identity instead of host root.
    if let Err(e) = crate::security::switch_user(state.user.as_deref(), state.rootless) {
        eprintln!("zerun exec: {e}");
        return 1;
    }

    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(&resolved[0]);
    cmd.args(resolved.iter().skip(1));
    cmd.env_clear();
    for (k, v) in &pairs {
        cmd.env(k, v);
    }

    let err = cmd.exec(); // only returns on failure
    eprintln!("zerun exec: execve {} failed: {err}", resolved[0]);
    1
}

fn upsert(env: &mut Vec<(String, String)>, key: &str, value: &str) {
    if let Some(slot) = env.iter_mut().find(|(k, _)| k == key) {
        slot.1 = value.to_string();
    } else {
        env.push((key.to_string(), value.to_string()));
    }
}
