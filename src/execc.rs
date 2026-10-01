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
//!   * before joining the mount namespace, C opens the host cgroup's
//!     `cgroup.procs` file; its descriptor remains valid after `/sys` becomes
//!     the container view;
//!   * D joins the container's cgroup through that retained descriptor, applies
//!     the same no_new_privs -> caps -> seccomp hardening as the container,
//!     chdir()s to the container working directory and execve()s the requested command.
//!
//! Joining the mount namespace means D shares the container's live rootfs and
//! its /proc /dev /sys mounts — exactly what `docker exec` shows. D is born as
//! a child of the container's PID 1 from the namespace's point of view (its
//! real parent C lives outside and reaps it through the host PID), so it is
//! reaped like any other container process.
use crate::error::ZResult;
use crate::state::{ContainerState, Status};
use crate::workload;
use std::fs::{File, OpenOptions};
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
    if state.paused {
        return Err(crate::zerr!(
            "container {} is paused; run `zerun unpause {}` before exec",
            state.id,
            state.id
        ));
    }
    if argv.is_empty() {
        return Err(crate::zerr!("exec: a command is required"));
    }

    // Validate the persisted cgroup path before entering the container's
    // namespaces. The state file is owner-only in normal operation, but it is
    // still untrusted input: after setns(cgroup), resolving a path supplied by
    // the record could make `exec` write its worker PID into an unrelated
    // host cgroup. Keep the store-derived path and pass that authority down.
    let cgroup_path = match state.cgroup.as_deref() {
        Some(persisted) => {
            let expected = crate::cgroup::CgroupV2::container_path(&state.id)?;
            if Path::new(persisted) != expected {
                return Err(crate::zerr!(
                    "refusing cgroup path {} for container {} (expected {})",
                    persisted,
                    state.id,
                    expected.display()
                ));
            }
            Some(expected)
        }
        None => None,
    };

    // The joiner C.
    match crate::syscalls::fork_process() {
        Err(error) => Err(crate::zerr!("exec: fork: {error}")),
        Ok(0) => {
            let code = joiner(state, pid, cgroup_path.as_deref(), env_extra, workdir, argv);
            crate::syscalls::exit_process(code)
        }
        Ok(parent) => {
            // Wait for C, which exits with D's code.
            let (_, status) = crate::syscalls::wait_pid(parent, 0)?
                .ok_or_else(|| crate::zerr!("exec: waitpid returned no child"))?;
            Ok(crate::syscalls::wait_status_code(status).unwrap_or(1))
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
    cgroup_path: Option<&Path>,
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

    // After `setns(mnt)`, `/sys/fs/cgroup` resolves inside the container's
    // mount namespace, where the host cgroup path in lifecycle state is not
    // visible. Open the already-validated host cgroup file now and retain its
    // descriptor across every setns call.
    let cgroup_procs = match cgroup_path {
        Some(path) => match open_cgroup_procs(path) {
            Ok(file) => Some(file),
            Err(error) => {
                eprintln!("zerun exec: open cgroup {}: {error}", path.display());
                return 1;
            }
        },
        None => None,
    };

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
    match crate::syscalls::fork_process() {
        Err(error) => {
            eprintln!("zerun exec: fork: {error}");
            1
        }
        Ok(0) => {
            let code = worker(state, cgroup_procs.as_ref(), env_extra, workdir, argv);
            crate::syscalls::exit_process(code)
        }
        Ok(d) => {
            // C waits for D and mirrors its exit code to the CLI.
            let (_, status) = match crate::syscalls::wait_pid(d, 0) {
                Ok(Some(result)) => result,
                Ok(None) => {
                    eprintln!("zerun exec: waitpid returned no child");
                    return 1;
                }
                Err(error) => {
                    eprintln!("zerun exec: waitpid: {error}");
                    return 1;
                }
            };
            crate::syscalls::wait_status_code(status).unwrap_or(1)
        }
    }
}

/// setns into one namespace by fd, with a readable error.
fn setns(f: &File, what: &str) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    crate::syscalls::setns(f.as_raw_fd(), 0).map_err(|error| format!("setns({what}): {error}"))
}

/// The in-container worker: cgroup join, cwd, env, hardening, exec.
fn worker(
    state: &ContainerState,
    cgroup_procs: Option<&File>,
    env_extra: &[String],
    workdir: Option<&str>,
    argv: &[String],
) -> i32 {
    // Join the container's cgroup before exec so the child is accounted
    // against the same memory/cpu/pids limits. If the persisted cgroup has
    // disappeared or cannot be written, fail closed instead of running the
    // command outside the container's resource policy.
    if let Some(procs) = cgroup_procs {
        if let Err(error) = join_cgroup(procs, std::process::id()) {
            eprintln!("zerun exec: join cgroup: {error}");
            return 1;
        }
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
            let Some((k, v)) = kv.split_once('=') else {
                eprintln!("zerun exec: invalid environment entry in state: '{kv}'");
                return 1;
            };
            if let Err(e) = workload::validate_env_pair(k, v) {
                eprintln!("zerun exec: invalid environment entry in state: '{kv}': {e}");
                return 1;
            }
            pairs.push((k.to_string(), v.to_string()));
        }
    }
    for kv in env_extra {
        if let Err(e) = workload::validate_env_spec(kv) {
            eprintln!("zerun exec: invalid environment entry '{kv}': {e}");
            return 1;
        }
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

    // Older records predate per-container capability state and safely fall
    // back to the default set. Exact recorded sets include the empty set, so
    // `exec` cannot silently regain capabilities that `run --cap-drop ALL`
    // removed.
    let capabilities = match state.capabilities.as_deref() {
        Some(names) => match crate::security::CapabilitySet::from_names(names) {
            Ok(capabilities) => capabilities,
            Err(e) => {
                eprintln!("zerun exec: {e}");
                return 1;
            }
        },
        None => crate::security::CapabilitySet::default(),
    };
    let seccomp = state.seccomp.unwrap_or_default();
    if let Err(e) = crate::security::harden(seccomp, &capabilities) {
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

fn open_cgroup_procs(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .write(true)
        .open(path.join("cgroup.procs"))
}

fn join_cgroup(procs: &File, pid: u32) -> std::io::Result<()> {
    use std::io::Write;

    let mut procs = procs;
    procs.write_all(pid.to_string().as_bytes())
}

fn upsert(env: &mut Vec<(String, String)>, key: &str, value: &str) {
    if let Some(slot) = env.iter_mut().find(|(k, _)| k == key) {
        slot.1 = value.to_string();
    } else {
        env.push((key.to_string(), value.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::{join_cgroup, open_cgroup_procs};

    #[test]
    fn join_cgroup_writes_the_worker_pid() {
        let dir = std::env::temp_dir().join(format!(
            "zerun-exec-cgroup-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("cgroup.procs"), b"").unwrap();
        let procs = open_cgroup_procs(&dir).unwrap();
        join_cgroup(&procs, 1234).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("cgroup.procs")).unwrap(),
            "1234"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn join_cgroup_reports_missing_cgroup_files() {
        let dir = std::env::temp_dir().join(format!(
            "zerun-exec-missing-cgroup-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::write(&dir, b"not a directory").unwrap();
        assert!(open_cgroup_procs(&dir).is_err());
        let _ = std::fs::remove_file(&dir);
    }
}
