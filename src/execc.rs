//! `zerun exec` — join a running container and run a command inside it.
//!
//! Model (in-process; no re-exec needed):
//!
//!   * the CLI opens a pidfd for container PID 1, revalidates its persisted
//!     process identity, then forks a joiner (C) with that stable task handle;
//!   * C enters the target namespaces through that pidfd — the private `user`
//!     namespace first (only rootless containers have one), then the private
//!     mnt/uts/ipc/net/cgroup/pid namespaces in one operation;
//!   * before joining the mount namespace, C opens the host cgroup's
//!     `cgroup.procs` file; its descriptor remains valid after `/sys` becomes
//!     the container view;
//!   * D joins the container's cgroup through that retained descriptor, applies
//!     the same no_new_privs -> caps -> seccomp hardening as the container,
//!     chdir()s to the container working directory and execve()s the requested command.
//!
//! Joining the mount namespace means D shares the container's live rootfs and
//! its /proc /dev /sys mounts — exactly what `docker exec` shows. With a
//! private PID namespace D is born as a child of the container's PID 1 from
//! that namespace's point of view (its real parent C lives outside and reaps it
//! through the host PID). With `--pid host` D remains an ordinary process in
//! the host PID namespace.
use crate::error::ZResult;
use crate::pty::{self, PtyPair};
use crate::state::{ContainerState, Status};
use crate::workload;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::Path;

/// One `zerun exec` invocation. Keeping the borrowed inputs together avoids
/// threading the same state/environment/stdio context through every fork stage.
#[derive(Clone, Copy)]
pub struct ExecRequest<'a> {
    pub state: &'a ContainerState,
    pub env_extra: &'a [String],
    pub user_override: Option<&'a str>,
    pub workdir: Option<&'a str>,
    pub tty: bool,
    pub interactive: bool,
    pub argv: &'a [String],
}

/// Result of a non-interactive command intended for health probing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedResult {
    pub code: i32,
    pub timed_out: bool,
    pub output: String,
}

/// Join the running container and run `request.argv` with its environment.
/// Returns the command's exit code.
pub fn run(request: ExecRequest<'_>) -> ZResult<i32> {
    Ok(execute(request, None)?.code)
}

/// Run a command in the container with bounded combined stdout/stderr.
///
/// Unlike the CLI path this never touches the caller's terminal, and a command
/// that exceeds `timeout` is terminated as a process group. The public
/// namespace/cgroup/security machinery is shared with `zerun exec`.
pub fn run_captured(
    state: &ContainerState,
    argv: &[String],
    timeout: std::time::Duration,
    max_output: usize,
) -> ZResult<CapturedResult> {
    let request = ExecRequest {
        state,
        env_extra: &[],
        user_override: None,
        workdir: None,
        tty: false,
        interactive: false,
        argv,
    };
    execute(
        request,
        Some(CaptureOptions {
            timeout,
            max_output: max_output.max(1),
        }),
    )
}

#[derive(Clone, Copy)]
struct CaptureOptions {
    timeout: std::time::Duration,
    max_output: usize,
}

fn execute(request: ExecRequest<'_>, capture: Option<CaptureOptions>) -> ZResult<CapturedResult> {
    let state = request.state;
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
    if request.argv.is_empty() {
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

    // Pin the target process before forking the namespace joiner. Check the
    // persisted start time again after pidfd_open so a PID reused between the
    // initial state check and this operation is rejected before any setns.
    if let Some(expected) = state.pid_start_time {
        if crate::procinfo::process_start_time(pid) != Some(expected) {
            return Err(crate::zerr!(
                "container PID {pid} no longer matches its recorded process"
            ));
        }
    }
    let pidfd = crate::syscalls::pidfd_open(pid)?;
    if let Some(expected) = state.pid_start_time {
        if crate::procinfo::process_start_time(pid) != Some(expected) {
            return Err(crate::zerr!(
                "container PID {pid} no longer matches its recorded process"
            ));
        }
    }

    // The caller owns the PTY master and pump. A thread cannot be created in C
    // after it joins the container's PID namespace: the new thread would be a
    // child in that namespace while sharing C's address space, which the kernel
    // rejects. C therefore reports D's host PID so the caller can pump host
    // stdio, enforce a probe timeout, and kill D if setup fails.
    let pty_pair = if request.tty {
        Some(PtyPair::open()?)
    } else {
        None
    };
    let (pid_r, pid_w) = crate::syscalls::pipe2_cloexec()?;
    let mut capture_pipe = capture.map(|_| crate::syscalls::Pipe::new()).transpose()?;

    let owner_pid = crate::syscalls::process_id();

    // The joiner C.
    match crate::syscalls::fork_process() {
        Err(error) => {
            crate::syscalls::close(pid_r);
            crate::syscalls::close(pid_w);
            Err(crate::zerr!("exec: fork: {error}"))
        }
        Ok(0) => {
            crate::syscalls::close(pid_r);
            let capture_w = capture_pipe
                .as_ref()
                .map_or(-1, crate::syscalls::Pipe::write_fd);
            if let Some(pipe) = capture_pipe.as_ref() {
                crate::syscalls::close(pipe.read_fd());
            }
            if capture.is_some() {
                if let Err(error) = arm_parent_death_signal(owner_pid) {
                    eprintln!("zerun exec: probe joiner lifetime: {error}");
                    crate::syscalls::exit_process(1);
                }
            }
            let code = joiner(
                request,
                pidfd.as_raw_fd(),
                cgroup_path.as_deref(),
                pty_pair,
                pid_w,
                capture_w,
            );
            crate::syscalls::exit_process(code)
        }
        Ok(parent) => {
            crate::syscalls::close(pid_w);
            let exec_pid = match read_exec_pid(pid_r) {
                Ok(pid) => pid,
                Err(error) => {
                    crate::syscalls::close(pid_r);
                    let _ = crate::syscalls::kill(parent, libc::SIGKILL);
                    let _ = crate::syscalls::wait_pid(parent, 0);
                    return Err(crate::zerr!("exec: worker pid pipe: {error}"));
                }
            };
            crate::syscalls::close(pid_r);

            // The parent must not retain the capture write end, or the reader
            // would never observe EOF. C closes its copy after the worker fork.
            let capture_reader =
                if let (Some(pipe), Some(options)) = (capture_pipe.as_mut(), capture) {
                    pipe.close_write();
                    let read = pipe.take_read().expect("capture pipe read end");
                    Some(std::thread::spawn(move || {
                        read_capture(read, options.max_output, options.timeout)
                    }))
                } else {
                    None
                };

            let mut pty_pair = pty_pair;
            let pump = if request.tty {
                match exec_pid {
                    Some(exec_pid) => match start_pty_pump(&mut pty_pair, request.interactive) {
                        Ok(pump) => pump,
                        Err(error) => {
                            let _ = crate::syscalls::kill(exec_pid, libc::SIGKILL);
                            let _ = crate::syscalls::wait_pid(parent, 0);
                            if let Some(reader) = capture_reader {
                                let _ = reader.join();
                            }
                            return Err(error);
                        }
                    },
                    None => {
                        // C failed before forking D; there is no PTY consumer.
                        drop(pty_pair);
                        None
                    }
                }
            } else {
                None
            };

            let mut capture_wait_error = None;
            let (code, timed_out) = match capture {
                Some(options) => match exec_pid {
                    Some(exec_pid) => match wait_captured(parent, exec_pid, options.timeout) {
                        Ok(result) => result,
                        Err(error) => {
                            // A wait failure must not leave the probe worker and
                            // its joiner running after the monitor has recorded
                            // the failure. The bounded output reader then sees
                            // EOF (or its own deadline) and can be joined.
                            let _ = crate::syscalls::kill_process_group_if_exists(
                                exec_pid,
                                libc::SIGKILL,
                            );
                            let _ = crate::syscalls::kill_if_exists(parent, libc::SIGKILL);
                            let _ = crate::syscalls::wait_pid(parent, 0);
                            capture_wait_error = Some(error);
                            (1, false)
                        }
                    },
                    None => {
                        let (_, status) = crate::syscalls::wait_pid(parent, 0)?
                            .ok_or_else(|| crate::zerr!("exec: waitpid returned no child"))?;
                        (
                            crate::syscalls::wait_status_code(status).unwrap_or(1),
                            false,
                        )
                    }
                },
                None => {
                    let (_, status) = crate::syscalls::wait_pid(parent, 0)?
                        .ok_or_else(|| crate::zerr!("exec: waitpid returned no child"))?;
                    (
                        crate::syscalls::wait_status_code(status).unwrap_or(1),
                        false,
                    )
                }
            };
            if let Some(handle) = pump {
                let _ = handle.join();
            }
            let output = match capture_reader {
                Some(reader) => reader
                    .join()
                    .unwrap_or_else(|_| "health probe output reader panicked".to_string()),
                None => String::new(),
            };
            if let Some(error) = capture_wait_error {
                return Err(error);
            }
            Ok(CapturedResult {
                code,
                timed_out,
                output,
            })
        }
    }
}

/// Wait for the joiner while enforcing the probe deadline on the worker.
fn wait_captured(
    joiner_pid: i32,
    worker_pid: i32,
    timeout: std::time::Duration,
) -> ZResult<(i32, bool)> {
    let worker_pidfd = match crate::syscalls::pidfd_open_if_exists(worker_pid) {
        Ok(pidfd) => pidfd,
        Err(error) => {
            // The numeric process-group kill below still provides timeout
            // enforcement; losing the pidfd is diagnostic rather than fatal.
            eprintln!("zerun exec: open probe pidfd: {error}");
            None
        }
    };
    let started = std::time::Instant::now();
    loop {
        if let Some((_, status)) = crate::syscalls::wait_pid(joiner_pid, libc::WNOHANG)? {
            return Ok((
                crate::syscalls::wait_status_code(status).unwrap_or(1),
                false,
            ));
        }
        if started.elapsed() >= timeout {
            if let Some(pidfd) = worker_pidfd.as_ref() {
                if let Err(error) =
                    crate::syscalls::pidfd_send_signal_if_exists(pidfd.as_raw_fd(), libc::SIGKILL)
                {
                    eprintln!("zerun exec: stop timed-out worker: {error}");
                }
            }
            if let Err(error) =
                crate::syscalls::kill_process_group_if_exists(worker_pid, libc::SIGKILL)
            {
                eprintln!("zerun exec: stop timed-out process group: {error}");
            }
            let (_, status) = crate::syscalls::wait_pid(joiner_pid, 0)?
                .ok_or_else(|| crate::zerr!("exec: timed-out waitpid returned no child"))?;
            return Ok((crate::syscalls::wait_status_code(status).unwrap_or(1), true));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Tie a health-probe helper to the parent that must reap it. PDEATHSIG resets
/// across fork, so both the namespace joiner and its in-container worker arm it.
fn arm_parent_death_signal(owner_pid: i32) -> ZResult<()> {
    crate::syscalls::set_parent_death_signal(libc::SIGTERM)?;
    if crate::syscalls::parent_process_id() != owner_pid {
        return Err(crate::zerr!("probe parent exited during setup"));
    }
    Ok(())
}

/// Drain combined probe output while retaining only a bounded prefix.
///
/// A probe may fork a process that keeps the inherited pipe open after the
/// command itself exits. Polling instead of blocking forever makes output
/// collection obey the probe deadline; otherwise the health monitor would
/// stall even though its command timeout had already fired.
fn read_capture(
    read: std::os::fd::OwnedFd,
    max_output: usize,
    timeout: std::time::Duration,
) -> String {
    let started = std::time::Instant::now();
    let mut kept = Vec::with_capacity(max_output.min(4096));
    let mut truncated = false;
    let mut collection_timed_out = false;
    let mut buffer = [0u8; 4096];
    loop {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            collection_timed_out = true;
            break;
        }
        let millis = remaining.as_millis().min(i32::MAX as u128) as i32;
        let mut pollfd = libc::pollfd {
            fd: read.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        match crate::syscalls::poll_fds(std::slice::from_mut(&mut pollfd), millis.max(1)) {
            Ok(0) => continue,
            Ok(_) if pollfd.revents == 0 => continue,
            Ok(_) => {}
            Err(error) => {
                append_output_error(&mut kept, error);
                break;
            }
        }
        match crate::syscalls::read_fd(read.as_raw_fd(), &mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                let count = count as usize;
                let room = max_output.saturating_sub(kept.len());
                let take = room.min(count);
                kept.extend_from_slice(&buffer[..take]);
                truncated |= take < count;
            }
            Err(error) => {
                append_output_error(&mut kept, error);
                break;
            }
        }
    }
    // Ensure the ownership of the read descriptor is retained until the drain
    // finishes and is closed on every return path.
    drop(read);
    let mut output = String::from_utf8_lossy(&kept).into_owned();
    if truncated {
        output.push_str("\n[health probe output truncated]");
    }
    if collection_timed_out {
        output.push_str("\n[health probe output collection timed out]");
    }
    output
}

fn append_output_error(kept: &mut Vec<u8>, error: crate::error::ZError) {
    if !kept.is_empty() {
        kept.push(b'\n');
    }
    kept.extend_from_slice(format!("health probe output error: {error}").as_bytes());
}

/// Which namespace flags `exec` joins. Rootless containers enter their private
/// user namespace in a separate operation first; rootful containers skip it.
/// The remaining namespaces are entered atomically with one pidfd setns call.
/// Joining the PID namespace only affects children, so the worker is forked
/// afterward.
fn joiner(
    request: ExecRequest<'_>,
    pidfd: std::os::fd::RawFd,
    cgroup_path: Option<&Path>,
    mut pty_pair: Option<PtyPair>,
    pid_w: std::os::fd::RawFd,
    capture_w: std::os::fd::RawFd,
) -> i32 {
    let state = request.state;
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

    let (user_namespace, namespaces) =
        match namespace_flags(state.rootless, state.namespaces, &state.net) {
            Ok(flags) => flags,
            Err(error) => {
                eprintln!("zerun exec: {error}");
                return 1;
            }
        };
    if let Some(user_namespace) = user_namespace {
        if let Err(error) = crate::syscalls::setns(pidfd, user_namespace) {
            eprintln!("zerun exec: setns(user): {error}");
            return 1;
        }
    }
    if let Err(error) = crate::syscalls::setns(pidfd, namespaces) {
        eprintln!("zerun exec: setns(container namespaces): {error}");
        return 1;
    }
    // Joining a private PID namespace takes effect only for children; the
    // worker fork below is therefore the first process created inside it. When
    // the container shares the host PID namespace, C is already in it.

    let tty_master = pty_pair.as_ref().map_or(-1, PtyPair::master);
    let tty_slave = pty_pair.as_ref().map_or(-1, PtyPair::slave);

    // Second fork: D is born inside the container's PID namespace.
    match crate::syscalls::fork_process() {
        Err(error) => {
            eprintln!("zerun exec: fork: {error}");
            1
        }
        Ok(0) => {
            let code = worker(
                request,
                cgroup_procs.as_ref(),
                tty_master,
                tty_slave,
                capture_w,
            );
            crate::syscalls::exit_process(code)
        }
        Ok(d) => {
            if capture_w >= 0 {
                // Only D needs the probe output pipe. Closing C's copy here
                // lets the reader observe EOF as soon as the workload exits.
                crate::syscalls::close(capture_w);
            }
            if pid_w >= 0 {
                let result = crate::syscalls::write_all_fd(pid_w, &d.to_ne_bytes());
                crate::syscalls::close(pid_w);
                if let Err(error) = result {
                    eprintln!("zerun exec: report worker pid: {error}");
                    let _ = crate::syscalls::kill(d, libc::SIGKILL);
                    let _ = crate::syscalls::wait_pid(d, 0);
                    return 1;
                }
            }

            // The CLI owns the master; C must release both of its copies so
            // D's exit produces a clean PTY EOF for the host pump.
            if let Some(pair) = pty_pair.as_mut() {
                pair.release_slave();
                let master = pair.take_master();
                if master >= 0 {
                    crate::syscalls::close(master);
                }
            }

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

/// Select pidfd `setns` flags. User namespaces must be entered separately
/// first; joining PID takes effect only for children created afterward.
/// Namespaces explicitly shared with the host are already occupied by `exec`
/// and must not appear in the join mask (rootless callers may lack privileges
/// in the host namespace that owns them).
fn namespace_flags(
    rootless: bool,
    modes: crate::state::NamespaceModes,
    net: &str,
) -> ZResult<(Option<libc::c_int>, libc::c_int)> {
    use crate::state::{IpcMode, NamespaceMode};

    let user = rootless.then_some(libc::CLONE_NEWUSER);
    let mut rest = libc::CLONE_NEWNS | libc::CLONE_NEWCGROUP;
    if matches!(modes.uts, NamespaceMode::Private) {
        rest |= libc::CLONE_NEWUTS;
    }
    if !matches!(modes.ipc, IpcMode::Host) {
        rest |= libc::CLONE_NEWIPC;
    }
    match net {
        "host" => {}
        "none" | "bridge" => rest |= libc::CLONE_NEWNET,
        other => {
            return Err(crate::zerr!(
                "container has invalid persisted network mode '{other}'"
            ))
        }
    }
    if matches!(modes.pid, NamespaceMode::Private) {
        rest |= libc::CLONE_NEWPID;
    }
    Ok((user, rest))
}

/// The in-container worker: cgroup join, cwd, env, hardening, exec.
fn worker(
    request: ExecRequest<'_>,
    cgroup_procs: Option<&File>,
    tty_master: std::os::fd::RawFd,
    tty_slave: std::os::fd::RawFd,
    capture_w: std::os::fd::RawFd,
) -> i32 {
    let ExecRequest {
        state,
        env_extra,
        user_override,
        workdir,
        interactive,
        argv,
        ..
    } = request;
    // D inherited both PTY ends across the fork. The joiner owns the master,
    // and only the worker should retain the slave as its stdio.
    if tty_master >= 0 {
        crate::syscalls::close(tty_master);
    }
    if capture_w >= 0 {
        // The worker's real parent lives outside its new PID namespace, so
        // getppid() cannot validate it. PDEATHSIG still tracks the real task;
        // the joiner installed a checked signal before forking us.
        if let Err(error) = crate::syscalls::set_parent_death_signal(libc::SIGTERM) {
            eprintln!("zerun exec: probe lifetime: {error}");
            return 1;
        }
        if let Err(error) = crate::syscalls::set_process_group() {
            eprintln!("zerun exec: process group: {error}");
            return 1;
        }
    }
    if let Err(error) = configure_stdio(tty_slave, interactive, capture_w) {
        eprintln!("zerun exec: stdio: {error}");
        return 1;
    }

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
    if tty_slave >= 0 && workload::env_value(&pairs, "TERM").is_none() {
        pairs.push((
            "TERM".to_string(),
            std::env::var("TERM").unwrap_or_else(|_| "xterm".to_string()),
        ));
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
    let supplementary_groups = match state.group_add.as_deref() {
        Some(specs) => match crate::security::resolve_group_additions(specs, state.rootless) {
            Ok(groups) => groups,
            Err(error) => {
                eprintln!("zerun exec: {error}");
                return 1;
            }
        },
        None => Vec::new(),
    };
    if let Some(specs) = state.ulimits.as_deref() {
        let limits = match crate::rlimit::UlimitSet::from_specs(specs) {
            Ok(limits) => limits,
            Err(error) => {
                eprintln!("zerun exec: invalid persisted --ulimit: {error}");
                return 1;
            }
        };
        if let Err(error) = limits.apply() {
            eprintln!("zerun exec: {error}");
            return 1;
        }
    }
    if let Err(e) = crate::security::harden(
        seccomp,
        &capabilities,
        state.rootless,
        &supplementary_groups,
    ) {
        eprintln!("zerun exec: {e}");
        return 1;
    }

    // Drop to the requested user, falling back to the container's configured
    // identity. Resolution happens after entering the mount namespace so
    // named users come from the container's own /etc/passwd and /etc/group.
    if let Err(e) =
        crate::security::switch_user(user_override.or(state.user.as_deref()), state.rootless)
    {
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

/// Read the host PID of D from C. EOF means C failed before the worker fork.
fn read_exec_pid(fd: std::os::fd::RawFd) -> ZResult<Option<i32>> {
    let mut bytes = [0u8; std::mem::size_of::<i32>()];
    let mut read = 0;
    while read < bytes.len() {
        let n = crate::syscalls::read_fd(fd, &mut bytes[read..])?;
        if n == 0 {
            return Ok(None);
        }
        read += n as usize;
    }
    let pid = i32::from_ne_bytes(bytes);
    Ok((pid > 0).then_some(pid))
}

/// Attach the CLI-side PTY pump. The caller owns the joins and error cleanup.
fn start_pty_pump(
    pty_pair: &mut Option<PtyPair>,
    interactive: bool,
) -> ZResult<Option<std::thread::JoinHandle<()>>> {
    let Some(pair) = pty_pair.as_mut() else {
        return Ok(None);
    };
    pair.release_slave();
    let master = pair.take_master();
    match pty::attach(master, interactive) {
        Ok(handle) => Ok(Some(handle)),
        Err(error) => {
            crate::syscalls::close(master);
            Err(error)
        }
    }
}

/// Give the in-container worker the requested stdio. Without `exec -i`, stdin
/// is /dev/null just like a non-interactive `docker exec`; with `-t`, the PTY
/// slave becomes both stdio endpoints and the worker's controlling terminal.
fn configure_stdio(
    tty_slave: std::os::fd::RawFd,
    interactive: bool,
    capture_w: std::os::fd::RawFd,
) -> ZResult<()> {
    if capture_w >= 0 {
        crate::syscalls::redirect_stdin_devnull()?;
        crate::syscalls::dup2(capture_w, libc::STDOUT_FILENO)?;
        crate::syscalls::dup2(capture_w, libc::STDERR_FILENO)?;
        crate::syscalls::close(capture_w);
    } else if tty_slave >= 0 {
        crate::syscalls::redirect_stdio(tty_slave)?;
        crate::syscalls::new_session()?;
        crate::syscalls::set_controlling_terminal(tty_slave)?;
        crate::syscalls::close(tty_slave);
    } else if !interactive {
        crate::syscalls::redirect_stdin_devnull()?;
    }
    Ok(())
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
    use super::{join_cgroup, namespace_flags, open_cgroup_procs, read_capture, read_exec_pid};
    use crate::state::{NamespaceMode, NamespaceModes};
    use std::time::{Duration, Instant};

    #[test]
    fn user_namespace_is_joined_separately_before_other_namespaces() {
        let (user_namespace, namespaces) =
            namespace_flags(true, NamespaceModes::default(), "none").unwrap();
        assert_eq!(user_namespace, Some(libc::CLONE_NEWUSER));
        assert_eq!(
            namespaces,
            libc::CLONE_NEWNS
                | libc::CLONE_NEWUTS
                | libc::CLONE_NEWIPC
                | libc::CLONE_NEWNET
                | libc::CLONE_NEWCGROUP
                | libc::CLONE_NEWPID
        );
    }

    #[test]
    fn rootful_namespace_join_skips_the_initial_user_namespace() {
        let (user_namespace, namespaces) =
            namespace_flags(false, NamespaceModes::default(), "bridge").unwrap();
        assert_eq!(user_namespace, None);
        assert_ne!(namespaces & libc::CLONE_NEWUSER, libc::CLONE_NEWUSER);
        assert_ne!(namespaces & libc::CLONE_NEWPID, 0);
    }

    #[test]
    fn host_shared_namespaces_are_not_rejoined_by_exec() {
        let modes = NamespaceModes {
            pid: NamespaceMode::Host,
            ipc: crate::state::IpcMode::Host,
            uts: NamespaceMode::Host,
        };
        let (_, flags) = namespace_flags(false, modes, "host").unwrap();
        assert_eq!(flags & libc::CLONE_NEWPID, 0);
        assert_eq!(flags & libc::CLONE_NEWIPC, 0);
        assert_eq!(flags & libc::CLONE_NEWUTS, 0);
        assert_eq!(flags & libc::CLONE_NEWNET, 0);
        assert_ne!(flags & libc::CLONE_NEWNS, 0);
        assert_ne!(flags & libc::CLONE_NEWCGROUP, 0);
    }

    #[test]
    fn ipc_without_shm_still_joins_the_private_ipc_namespace() {
        let modes = NamespaceModes {
            ipc: crate::state::IpcMode::None,
            ..NamespaceModes::default()
        };
        let (_, flags) = namespace_flags(false, modes, "none").unwrap();
        assert_ne!(flags & libc::CLONE_NEWIPC, 0);
    }

    #[test]
    fn malformed_persisted_network_mode_is_rejected() {
        assert!(namespace_flags(false, NamespaceModes::default(), "network-ish").is_err());
    }

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
    fn worker_pid_pipe_round_trips_and_detects_an_early_child_failure() {
        let (read, write) = crate::syscalls::pipe2_cloexec().unwrap();
        crate::syscalls::write_all_fd(write, &4242i32.to_ne_bytes()).unwrap();
        crate::syscalls::close(write);
        assert_eq!(read_exec_pid(read).unwrap(), Some(4242));
        crate::syscalls::close(read);

        let (read, write) = crate::syscalls::pipe2_cloexec().unwrap();
        crate::syscalls::close(write);
        assert_eq!(read_exec_pid(read).unwrap(), None);
        crate::syscalls::close(read);
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

    #[test]
    fn captured_output_is_bounded_and_closes_at_eof() {
        let mut pipe = crate::syscalls::Pipe::new().unwrap();
        crate::syscalls::write_all_fd(pipe.write_fd(), b"health-output").unwrap();
        pipe.close_write();
        let read = pipe.take_read().expect("pipe read end");
        assert_eq!(
            read_capture(read, 6, Duration::from_secs(1)),
            "health\n[health probe output truncated]"
        );
    }

    #[test]
    fn captured_output_does_not_hang_when_a_descendant_holds_the_pipe() {
        let mut pipe = crate::syscalls::Pipe::new().unwrap();
        crate::syscalls::write_all_fd(pipe.write_fd(), b"partial").unwrap();
        let read = pipe.take_read().expect("pipe read end");
        let started = Instant::now();
        let output = read_capture(read, 32, Duration::from_millis(25));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(output.starts_with("partial"));
        assert!(output.contains("output collection timed out"));
        drop(pipe);
    }
}
