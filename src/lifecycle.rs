//! Detached-container lifecycle (M5): the per-container **reaper**.
//!
//! `run -d` forks once: the foreground CLI keeps only the job of reporting
//! "container started" (id) and exits; the forked child becomes the reaper —
//! a per-container, daemonless process that
//!
//!   1. captures container stdout/stderr into a timestamped console.log,
//!   2. runs the normal isolation path (`namespace::run_container_with_hook`),
//!   3. persists "running" state and releases the CLI exactly when the
//!      workload has exec'd,
//!   4. waitpid()s the container, persists "exited" + exit code, removes the
//!      per-run overlay, then exits itself (Pss target < 1 MB while waiting —
//!      the design doc's §8.2 budget for the whole reaper).
//!
//! Crash reconcile (`ze ps`, `ze rm -f`) also lives here: when a state file
//! says "running" but the PID is gone, the reaper died without cleaning up,
//! so the leftover nft table / veth / cgroup / IPAM record are reclaimed.
use crate::error::ZResult;
use crate::fsutil;
use crate::namespace::{run_container_with_hook, RunSpec};
use crate::state::{self, ContainerState, Status};
use crate::store::{ContainerFs, Store};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::RawFd;
use std::path::Path;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The detached reaper's whole job. Runs the container, persists state, then
/// returns the exit code (the caller `_exit`s). `overlay_dir` (if any) is
/// removed after the container exits; `started_w` carries the "0" (started)
/// or "1:<error>" signal back to the `run -d` CLI.
pub fn run_detached(
    store: Store,
    spec: RunSpec,
    container_fs: Option<ContainerFs>,
    remove_state: bool,
    started_w: RawFd,
    log_path: &Path,
    previous_log_fd: RawFd,
) -> i32 {
    let id = spec.id.clone();
    // Replace inherited stdio with a timestamping collector before clone so
    // the container's real stdout/stderr are the collector's write ends.
    let mut captured_log = match CapturedLog::install(log_path, previous_log_fd) {
        Ok(log) => log,
        Err(e) => {
            eprintln!("zerun: install log collector: {e}");
            let msg = format!("1: install log collector: {e}\n");
            let _ = write_all(started_w, msg.as_bytes());
            let _ = unsafe { libc::close(started_w) };
            return 1;
        }
    };
    let mut signaled = false;
    let mut code = 1;
    let result = run_container_with_hook(spec, |info| {
        // Persist "running" before releasing the CLI so `ze ps` never sees a
        // Created-but-alive container.
        if let Some(mut st) = ContainerState::load(&store, &id) {
            st.status = Status::Running;
            st.pid = Some(info.pid);
            st.started = Some(state::now_rfc3339());
            st.ip = info.ip;
            st.table = info.table.clone();
            st.veth = info.veth.clone();
            st.cgroup = info.cgroup.clone();
            let _ = st.save();
        }
        signaled = true;
        let _ = write_all(started_w, b"0\n");
        let _ = unsafe { libc::close(started_w) };
    });
    match result {
        Ok(c) => code = c,
        Err(e) => {
            // Setup failed before the child could exec (cgroup create, bridge
            // allocation...). The error pipe path inside namespace.rs prints its
            // own details for post-clone failures; this is the pre-clone kind.
            let msg = format!("1: {e}\n");
            let _ = write_all(started_w, msg.as_bytes());
            let _ = unsafe { libc::close(started_w) };
            eprintln!("zerun: {e}");
        }
    }
    // If the hook never fired, the child failed during setup (the error pipe
    // path in namespace.rs already printed details to our log) and the CLI is
    // still blocked on the started pipe: tell it.
    if !signaled {
        let msg = b"1: container setup failed (see console.log)\n";
        let _ = write_all(started_w, msg);
        let _ = unsafe { libc::close(started_w) };
    }

    // Close the pipe write ends and flush the final partial line before the
    // state record is marked Exited.
    captured_log.finish();

    // Final state: exited.
    if let Some(mut st) = ContainerState::load(&store, &id) {
        st.status = Status::Exited;
        st.exit_code = Some(code);
        st.finished = Some(state::now_rfc3339());
        let _ = st.save();
    }
    if let Some(fs) = container_fs {
        store.cleanup_container_fs(&fs);
    }
    if remove_state {
        let dir = state::ContainerState::dir(&store, &id);
        fsutil::remove_dir_all_quiet(&dir);
    }
    code
}

/// Background pipe -> timestamped console.log collector.
struct CapturedLog {
    reader: Option<JoinHandle<()>>,
}

impl CapturedLog {
    fn install(log_path: &Path, previous_log_fd: RawFd) -> ZResult<Self> {
        let log_file = OpenOptions::new().append(true).open(log_path)?;
        let (read_fd, write_fd) = crate::syscalls::pipe2_cloexec()?;

        // Detached stdin has no terminal. stdout/stderr become the pipe read by
        // the collector; the container inherits these write ends through clone.
        // The original log File is no longer needed because the collector owns
        // its own append-mode handle.
        crate::syscalls::redirect_stdin_devnull()?;
        crate::syscalls::dup2(write_fd, libc::STDOUT_FILENO)?;
        crate::syscalls::dup2(write_fd, libc::STDERR_FILENO)?;
        crate::syscalls::close(write_fd);
        crate::syscalls::close(previous_log_fd);

        let reader = std::thread::Builder::new()
            .name("zerun-log".to_string())
            .stack_size(64 * 1024)
            .spawn(move || collect_timestamped(read_fd, log_file))?;
        Ok(Self {
            reader: Some(reader),
        })
    }

    /// Signal EOF to the collector and wait for it to flush.
    fn finish(&mut self) {
        crate::syscalls::close(libc::STDOUT_FILENO);
        crate::syscalls::close(libc::STDERR_FILENO);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn collect_timestamped(read_fd: RawFd, mut output: File) {
    let mut pending: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8 * 1024];
    loop {
        match crate::syscalls::read_fd(read_fd, &mut buf) {
            Ok(0) => break,
            Ok(n) => pending.extend_from_slice(&buf[..n as usize]),
            Err(_) => break,
        }
        while let Some(end) = pending.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = pending.drain(..=end).collect();
            if write_timestamped_line(&mut output, &line).is_err() {
                crate::syscalls::close(read_fd);
                return;
            }
        }
    }
    if !pending.is_empty() {
        let _ = write_timestamped_line(&mut output, &pending);
    }
    crate::syscalls::close(read_fd);
}

fn write_timestamped_line(output: &mut File, line: &[u8]) -> std::io::Result<()> {
    output.write_all(state::now_rfc3339_nanos().as_bytes())?;
    output.write_all(b"\t")?;
    output.write_all(line)
}

/// Reconcile one stale "running" record (reaper died): mark it exited and
/// reclaim its host-side resources (nft table, veth, cgroup, IPAM slot).
/// Returns true when the record changed.
pub fn reconcile_stale(store: &Store, st: &mut ContainerState) -> bool {
    if st.status != Status::Running || st.pid_alive() {
        return false;
    }
    // The PID is gone but state still says running: the reaper was killed or
    // the host rebooted. Best-effort reclaim of everything the reaper would
    // have torn down.
    if let (Some(veth), Some(table)) = (st.veth.as_deref(), st.table.as_deref()) {
        crate::network::teardown_named(veth, table);
    }
    if let Some(cg) = st.cgroup.as_deref() {
        let _ = std::fs::remove_dir(cg);
    }
    if st.net == "bridge" {
        crate::network::release_ip(store.run_root(), &st.id);
    }
    st.status = Status::Exited;
    st.exit_code = st.exit_code.or(Some(137)); // SIGKILL-ish default
    st.finished = Some(state::now_rfc3339());
    st.table = None;
    st.veth = None;
    st.cgroup = None;
    // The per-run overlay would normally have been removed by the reaper right
    // after the container exited; reclaim it here when the reaper never got to.
    if let Some(ov) = st.overlay.take() {
        fsutil::remove_dir_all_quiet(Path::new(&ov));
    }
    true
}

/// After `stop`/`rm -f` has killed a container's PID: normally the live reaper
/// observes the death and persists "exited" itself within milliseconds. Wait a
/// short grace period for that write; when the reaper is gone too (crash), do
/// the reconcile in its place so no stale "running" record survives.
pub fn settle_exit(store: &Store, id: &str) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        match ContainerState::load(store, id) {
            None => return, // --rm already removed the record
            Some(st) if st.status != Status::Running => return,
            Some(_) => {}
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if let Some(mut st) = ContainerState::load(store, id) {
        if st.status == Status::Running && !st.pid_alive() && reconcile_stale(store, &mut st) {
            let _ = st.save();
        }
    }
}

/// Reclaim host-side resources for an exited container that still holds them
/// (used by `rm` on records whose reaper did not clean up).
pub fn reclaim_resources(store: &Store, st: &ContainerState) {
    if let (Some(veth), Some(table)) = (st.veth.as_deref(), st.table.as_deref()) {
        crate::network::teardown_named(veth, table);
    }
    if st.net == "bridge" {
        crate::network::release_ip(store.run_root(), &st.id);
    }
}

/// Write all of `buf` to `fd`, tolerating EINTR (best effort).
fn write_all(fd: RawFd, buf: &[u8]) -> ZResult<()> {
    let mut off = 0;
    while off < buf.len() {
        let n = unsafe {
            libc::write(
                fd,
                buf[off..].as_ptr() as *const libc::c_void,
                buf.len() - off,
            )
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e.into());
        }
        off += n as usize;
    }
    Ok(())
}
