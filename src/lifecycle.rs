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
use crate::logs::LogOptions;
use crate::namespace::{run_container_with_report, RunSpec};
use crate::state::{self, ContainerState, Status};
use crate::store::{ContainerFs, Store};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Maximum bytes buffered for one newline-terminated console record.
///
/// A workload can write arbitrarily many bytes without a newline. Retaining
/// that partial line in memory would let it grow the reaper without bound, so
/// oversized lines are split into timestamped records. Splitting only the
/// on-disk log keeps the `attach` stream byte-for-byte faithful.
const MAX_LOG_RECORD_BYTES: usize = 64 * 1024;

/// Upper bound on simultaneous `zerun attach` clients for one container.
///
/// The socket is owner-only, but a local process can still open it repeatedly.
/// Keep the reaper's descriptor and fan-out memory bounded even when clients
/// stop reading or disconnect while the workload is silent.
const MAX_ATTACH_CLIENTS: usize = 32;

/// Bounded backoff between automatic restart attempts.
const RESTART_INITIAL_DELAY: Duration = Duration::from_millis(100);
const RESTART_MAX_DELAY: Duration = Duration::from_secs(1);
/// A run at least this long resets the restart backoff.
const RESTART_STABLE_AFTER: Duration = Duration::from_secs(10);
/// Maximum time the reaper waits for a concurrent lifecycle command.
const RESTART_LOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// Persist the running transition before the detached CLI is released.
///
/// This is deliberately a fallible boundary: a detached run without a durable
/// running record cannot be safely addressed by later lifecycle commands.
fn persist_started_state(
    store: &Store,
    id: &str,
    info: &crate::namespace::StartedInfo,
) -> ZResult<()> {
    let mut st = ContainerState::load(store, id)
        .ok_or_else(|| crate::zerr!("detached state for {id} disappeared before start"))?;
    st.status = Status::Running;
    st.paused = false;
    st.restart_pending = false;
    st.pid = Some(info.pid);
    st.pid_start_time = info.pid_start_time;
    st.started = Some(state::now_rfc3339());
    st.finished = None;
    st.exit_code = None;
    st.metrics = None;
    st.health = st
        .healthcheck
        .as_ref()
        .map(|_| state::HealthState::starting());
    st.ip = info.ip;
    st.table = info.table.clone();
    st.veth = info.veth.clone();
    st.cgroup = info.cgroup.clone();
    st.save(store)
}

/// Console-log destination passed across the detached reaper fork.
pub struct LogTarget<'a> {
    pub path: &'a Path,
    pub previous_fd: RawFd,
    pub options: LogOptions,
}

/// Run the detached workload, applying its restart policy between attempts.
///
/// The caller `_exit`s with the final workload code. `started_w` carries the
/// "0" (started) or "1:<error>" signal back to the `run -d` CLI exactly once.
pub fn run_detached(
    store: Store,
    spec: RunSpec,
    container_fs: Option<ContainerFs>,
    remove_state: bool,
    started_w: RawFd,
    log: LogTarget<'_>,
) -> i32 {
    let id = spec.id.clone();
    // Replace inherited stdio with a timestamping collector before launching
    // the namespace supervisor so the container's real stdout/stderr are the
    // collector's write ends. The collector and attach hub remain installed
    // across automatic restarts.
    let mut captured_log = match CapturedLog::install(log.path, log.previous_fd, log.options) {
        Ok(log) => log,
        Err(e) => {
            eprintln!("zerun: install log collector: {e}");
            let msg = format!("1: install log collector: {e}\n");
            let _ = write_all(started_w, msg.as_bytes());
            crate::syscalls::close(started_w);
            return 1;
        }
    };

    let mut signaled = false;
    let mut started_once = false;
    let mut start_error = None;
    let mut code;
    let mut backoff = RESTART_INITIAL_DELAY;
    let mut held_restart_lock: Option<state::ContainerOperationLock> = None;
    let mut health_monitor: Option<crate::health::Monitor> = None;
    // Keep the operation lock until log/attach cleanup has finished so a
    // `wait` that observes the final state cannot race a manual `start`.
    let mut terminal_lock: Option<state::ContainerOperationLock> = None;
    let reaper_pid = crate::syscalls::process_id();
    let reaper_start_time = crate::procinfo::process_start_time(reaper_pid);
    if let Err(error) = persist_reaper_claim(&store, &id, reaper_pid, reaper_start_time) {
        eprintln!("zerun: claim detached container {id}: {error}");
        let msg = format!("1: claim detached container: {error}\n");
        let _ = write_all(started_w, msg.as_bytes());
        crate::syscalls::close(started_w);
        captured_log.finish();
        return 1;
    }

    loop {
        let attempt_started = Instant::now();
        // A restart carries the lifecycle lock from the previous terminal
        // state through backoff and this attempt. If setup fails before the
        // started hook, it remains held for the next terminal-state write.
        let mut start_lock = held_restart_lock.take();
        code = 1;
        let result = run_container_with_report(spec.clone(), |info| {
            // Persist "running" before releasing the CLI so `ze ps` never sees
            // a Created-but-alive container. On an automatic retry this also
            // replaces the previous terminal attempt in one atomic write.
            persist_started_state(&store, &id, info)?;
            started_once = true;
            // The reaper owns this lock only through the next successful
            // exec. Releasing it here lets `stop`/`kill` address the new run.
            drop(start_lock.take());
            health_monitor =
                crate::health::Monitor::spawn(&store, &id, info.pid, info.pid_start_time)?;
            if !signaled {
                signaled = true;
                let _ = write_all(started_w, b"0\n");
                crate::syscalls::close(started_w);
            }
            Ok(())
        });
        let attempt_elapsed = attempt_started.elapsed();
        if let Some(monitor) = health_monitor.take() {
            monitor.stop();
        }

        let mut metrics = None;
        match result {
            Ok(exit) => {
                code = exit.code;
                metrics = exit.metrics;
            }
            Err(error) => {
                // Setup failed before the child could exec (cgroup create,
                // bridge allocation...). The error pipe path inside
                // namespace.rs prints its own details after the supervisor
                // starts; this is the pre-launch kind. The retry loop resets
                // `code` to one before every attempt.
                start_error = Some(error.to_string());
                eprintln!("zerun: {error}");
            }
        }

        // Coordinate the terminal write with lifecycle commands. The reaper
        // identity in state keeps `ps`/`wait` from mistaking the short gap
        // after a workload exits for a crashed reaper.
        let operation_lock = match start_lock.or_else(|| {
            state::ContainerOperationLock::acquire(&store, &id, RESTART_LOCK_TIMEOUT).ok()
        }) {
            Some(lock) => lock,
            None => {
                eprintln!(
                    "zerun: warning: could not persist terminal state for container {id}: lifecycle lock busy"
                );
                break;
            }
        };

        let Some(mut st) = ContainerState::load(&store, &id) else {
            // `rm` or `--rm` removed the record (the latter cannot be combined
            // with an enabled restart policy).
            break;
        };
        if !reaper_owns_state(&st, reaper_pid, reaper_start_time) {
            // A manual start replaced this reaper while it was unwinding.
            break;
        }
        st.metrics = metrics.or(st.metrics);
        st.status = Status::Exited;
        st.paused = false;
        st.exit_code = Some(code);
        st.finished = Some(state::now_rfc3339());
        let policy = st.restart_policy;
        let completed_restarts = st.restart_count;
        let restart_denied = state::restart_is_suppressed(&store, &id);
        let will_restart =
            started_once && !restart_denied && policy.should_restart(code, completed_restarts);

        if will_restart {
            // Count the attempt now, while its terminal state is written. A
            // crash during setup therefore cannot make a finite policy spin.
            st.restart_count = st.restart_count.saturating_add(1);
            st.restart_pending = true;
        } else {
            st.restart_pending = false;
            clear_reaper_claim(&mut st);
        }
        if let Err(error) = st.save(&store) {
            eprintln!(
                "zerun: warning: failed to persist final state for container {}: {error}",
                st.id
            );
            break;
        }
        if !will_restart {
            terminal_lock = Some(operation_lock);
            break;
        }

        let delay = if attempt_elapsed >= RESTART_STABLE_AFTER {
            RESTART_INITIAL_DELAY
        } else {
            backoff
        };
        backoff = next_restart_delay(delay);
        // Do not hold the lifecycle lock while sleeping. Interactive commands
        // must be able to mark a fast crash loop as stopped instead of racing
        // the reaper for a lock it would otherwise never yield.
        drop(operation_lock);
        std::thread::sleep(delay);

        let lock = match state::ContainerOperationLock::acquire(&store, &id, RESTART_LOCK_TIMEOUT) {
            Ok(lock) => lock,
            Err(error) => {
                eprintln!("zerun: warning: automatic restart for container {id} stopped: {error}");
                break;
            }
        };
        if state::restart_is_suppressed(&store, &id) {
            finish_cancelled_restart(&store, &id, reaper_pid, reaper_start_time);
            terminal_lock = Some(lock);
            break;
        }
        match ContainerState::load(&store, &id) {
            Some(current)
                if current.restart_pending
                    && reaper_owns_state(&current, reaper_pid, reaper_start_time) => {}
            _ => {
                terminal_lock = Some(lock);
                break;
            }
        }
        held_restart_lock = Some(lock);
    }

    // If the initial attempt never reached exec, the CLI is still blocked on
    // the started pipe. Report the most precise error available.
    if !signaled {
        let msg = if let Some(error) = start_error {
            format!("1: {error}\n")
        } else {
            "1: container setup failed (see console.log)\n".to_string()
        };
        let _ = write_all(started_w, msg.as_bytes());
        crate::syscalls::close(started_w);
    }

    // Close the pipe write ends and flush the final partial line before the
    // state record is marked Exited.
    captured_log.finish();

    // Keep the writable layer for an addressable exited container so it can be
    // committed or inspected later. `--rm` retains Docker's remove-on-exit
    // behavior; `rm` cleans up any other stopped container's layer.
    if let Some(fs) = container_fs {
        if remove_state {
            store.cleanup_container_fs(&fs);
        }
    }
    // Attach clients get the exit status as the very last bytes on the
    // socket, then EOF.
    captured_log.release_attach(code);
    if remove_state {
        if let Some(st) = ContainerState::load(&store, &id) {
            crate::remove_anonymous_volumes(&store, &st.id, &st.anonymous_volumes);
        }
        let dir = state::ContainerState::dir(&store, &id);
        fsutil::remove_dir_all_quiet(&dir);
    }
    drop(terminal_lock);
    code
}

fn persist_reaper_claim(store: &Store, id: &str, pid: i32, start_time: Option<u64>) -> ZResult<()> {
    let mut st = ContainerState::load(store, id)
        .ok_or_else(|| crate::zerr!("detached state for {id} disappeared before reaper claim"))?;
    st.reaper_pid = Some(pid);
    st.reaper_start_time = start_time;
    st.restart_pending = false;
    st.save(store)
}

fn reaper_owns_state(st: &ContainerState, pid: i32, start_time: Option<u64>) -> bool {
    st.reaper_pid == Some(pid) && st.reaper_start_time == start_time
}

fn clear_reaper_claim(st: &mut ContainerState) {
    st.reaper_pid = None;
    st.reaper_start_time = None;
}

fn finish_cancelled_restart(store: &Store, id: &str, pid: i32, start_time: Option<u64>) {
    let Some(mut st) = ContainerState::load(store, id) else {
        return;
    };
    if !reaper_owns_state(&st, pid, start_time) {
        return;
    }
    st.restart_pending = false;
    clear_reaper_claim(&mut st);
    if let Err(error) = st.save(store) {
        eprintln!("zerun: warning: failed to persist stopped restart for {id}: {error}");
    }
}

fn next_restart_delay(delay: Duration) -> Duration {
    delay.saturating_mul(2).min(RESTART_MAX_DELAY)
}

/// Background pipe -> timestamped console.log collector.
struct CapturedLog {
    reader: Option<JoinHandle<()>>,
    /// Live-output fan-out for `zerun attach` (None when the socket could
    /// not be bound; attach then reports no socket instead of failing runs).
    attach: Option<AttachHub>,
}

impl CapturedLog {
    fn install(log_path: &Path, previous_log_fd: RawFd, log_options: LogOptions) -> ZResult<Self> {
        let log_file = RotatingLog::open(log_path, log_options)?;
        let (read_fd, write_fd) = crate::syscalls::pipe2_cloexec()?;

        // Detached stdin has no terminal. stdout/stderr become the pipe read by
        // the collector; the container inherits these write ends through fork.
        // The original log File is no longer needed because the collector owns
        // its own append-mode handle.
        crate::syscalls::redirect_stdin_devnull()?;
        crate::syscalls::dup2(write_fd, libc::STDOUT_FILENO)?;
        crate::syscalls::dup2(write_fd, libc::STDERR_FILENO)?;
        crate::syscalls::close(write_fd);
        crate::syscalls::close(previous_log_fd);

        // Live attach socket next to console.log; a failed bind degrades to
        // log-only operation (attach reports the missing socket clearly).
        let sock_path = log_path.with_file_name("attach.sock");
        let attach = match AttachHub::bind(&sock_path) {
            Ok(hub) => Some(hub),
            Err(e) => {
                eprintln!("zerun: attach socket unavailable: {e}");
                None
            }
        };
        let attach_clients = attach.as_ref().map(|hub| Arc::clone(&hub.clients));

        let reader = std::thread::Builder::new()
            .name("zerun-log".to_string())
            .stack_size(64 * 1024)
            .spawn(move || collect_timestamped(read_fd, log_file, attach_clients))?;
        Ok(Self {
            reader: Some(reader),
            attach,
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

    /// Tell attached clients the final exit status and remove the socket.
    fn release_attach(&self, code: i32) {
        if let Some(hub) = &self.attach {
            hub.close_all(code);
        }
    }
}

/// Bounded writer for the active console log.
///
/// Rotation is performed by the collector thread, so there is no cross-process
/// file lock. `max_files` counts the active file and all numbered archives.
struct RotatingLog {
    active: std::path::PathBuf,
    file: File,
    written: u64,
    options: LogOptions,
}

impl RotatingLog {
    fn open(active: &Path, options: LogOptions) -> std::io::Result<Self> {
        let file = OpenOptions::new().append(true).open(active)?;
        // Logs may contain application secrets. Tighten files created by older
        // versions as well as newly-created files before the collector writes.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        let written = file.metadata()?.len();
        Ok(Self {
            active: active.to_path_buf(),
            file,
            written,
            options,
        })
    }

    fn write_record(&mut self, timestamp: &[u8], line: &[u8]) -> std::io::Result<()> {
        let record_len = timestamp.len().saturating_add(1).saturating_add(line.len()) as u64;
        if self.options.max_size > 0
            && self.written > 0
            && self.written.saturating_add(record_len) > self.options.max_size
        {
            self.rotate()?;
        }
        self.file.write_all(timestamp)?;
        self.file.write_all(b"\t")?;
        self.file.write_all(line)?;
        self.written = self.written.saturating_add(record_len);
        Ok(())
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        // `rotate` holds `&mut self`, so no writes can race the renames. The
        // old descriptor is replaced below, after it has been renamed into the
        // archive set; until then it remains the only handle to that inode.
        let max_files = self.options.max_files.max(1);
        if max_files > 1 {
            for index in (1..max_files - 1).rev() {
                let from = numbered_path(&self.active, index);
                let to = numbered_path(&self.active, index + 1);
                match std::fs::rename(&from, &to) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
            }
            match std::fs::rename(&self.active, numbered_path(&self.active, 1)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        } else {
            let _ = std::fs::remove_file(&self.active);
        }
        // Existing archives may have been created before private log files
        // were enforced. Secure every retained inode after the rename pass.
        for index in 1..max_files {
            let archive = numbered_path(&self.active, index);
            match std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o600)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        let replacement = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&self.active)?;
        drop(std::mem::replace(&mut self.file, replacement));
        self.written = 0;
        Ok(())
    }
}

fn numbered_path(active: &Path, index: usize) -> std::path::PathBuf {
    let mut name = active.as_os_str().to_os_string();
    name.push(format!(".{index}"));
    std::path::PathBuf::from(name)
}

/// Fan-out hub for `zerun attach` clients over a per-container unix socket.
///
/// The collector writes every captured line as a length-prefixed frame;
/// failed clients are dropped lazily. The reaper sends a zero-length control
/// frame carrying the exit status, so workload bytes are never metadata.
struct AttachHub {
    clients: Arc<Mutex<Vec<UnixStream>>>,
    sock_path: std::path::PathBuf,
}

impl AttachHub {
    fn bind(sock_path: &Path) -> ZResult<AttachHub> {
        let _ = std::fs::remove_file(sock_path); // stale socket from a crash
        let listener = UnixListener::bind(sock_path)
            .map_err(|e| crate::zerr!("bind {}: {e}", sock_path.display()))?;
        // Owner-only: the socket streams container output.
        let _ = std::fs::set_permissions(sock_path, std::fs::Permissions::from_mode(0o600));
        let clients: Arc<Mutex<Vec<UnixStream>>> = Arc::default();
        let worker_clients = Arc::clone(&clients);
        std::thread::Builder::new()
            .name("zerun-attach".to_string())
            .spawn(move || {
                // Blocks on accept until the reaper process exits; the
                // kernel closes the listener fd with the process.
                let mut warned_full = false;
                for stream in listener.incoming() {
                    match stream {
                        Ok(s) => {
                            // Keep the collector non-blocking even if an
                            // attached client stops reading; such a client is
                            // dropped and can catch up with `zerun logs`.
                            let _ = s.set_nonblocking(true);
                            if let Ok(mut list) = worker_clients.lock() {
                                if register_attach_client(&mut list, s) {
                                    warned_full = false;
                                } else if !warned_full {
                                    eprintln!(
                                        "zerun: warn: attach client limit ({MAX_ATTACH_CLIENTS}) reached; dropping new connection"
                                    );
                                    warned_full = true;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
            })?;
        Ok(AttachHub {
            clients,
            sock_path: sock_path.to_path_buf(),
        })
    }

    /// Send the final exit status and disconnect everyone (reaper exit).
    fn close_all(&self, code: i32) {
        if let Ok(mut list) = self.clients.lock() {
            for mut client in list.drain(..) {
                let mut frame = 0u32.to_be_bytes().to_vec();
                frame.extend_from_slice(&code.to_be_bytes());
                let _ = client.write_all(&frame);
            }
        }
        let _ = std::fs::remove_file(&self.sock_path);
    }
}

/// Drop disconnected clients and reserve one slot for a new attachment.
fn register_attach_client(clients: &mut Vec<UnixStream>, client: UnixStream) -> bool {
    clients.retain(|attached| crate::syscalls::socket_peer_connected(attached.as_raw_fd()));
    if clients.len() >= MAX_ATTACH_CLIENTS {
        return false;
    }
    clients.push(client);
    true
}

/// Write `chunk` to every attached client; failed clients are dropped.
fn broadcast(clients: &Mutex<Vec<UnixStream>>, chunk: &[u8]) {
    if chunk.is_empty() {
        return;
    }
    let Ok(mut list) = clients.lock() else {
        return;
    };
    let mut frame = (chunk.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(chunk);
    list.retain_mut(|client| client.write_all(&frame).is_ok());
}

/// One message from the attach stream. EOF is separate from the explicit
/// control frame because the latter carries the workload's exact exit code.
#[derive(Debug, PartialEq, Eq)]
pub enum AttachFrame {
    Data(Vec<u8>),
    Exit(i32),
    Eof,
}

/// Read one attach-socket frame, preserving the final exit status.
pub fn read_attach_frame(stream: &mut UnixStream) -> std::io::Result<AttachFrame> {
    let mut prefix = [0u8; 4];
    loop {
        match stream.read(&mut prefix[..1]) {
            Ok(0) => return Ok(AttachFrame::Eof),
            Ok(1) => break,
            Ok(_) => unreachable!("one-byte read returned more than one byte"),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    stream.read_exact(&mut prefix[1..])?;
    let len = u32::from_be_bytes(prefix);
    if len == 0 {
        let mut code = [0u8; 4];
        stream.read_exact(&mut code)?;
        return Ok(AttachFrame::Exit(i32::from_be_bytes(code)));
    }
    // The reaper only writes pipe-sized workload frames; retain a hard bound
    // anyway so a malformed local stream cannot force a huge allocation.
    if len > 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "attach frame too large",
        ));
    }
    let mut chunk = vec![0u8; len as usize];
    stream.read_exact(&mut chunk)?;
    Ok(AttachFrame::Data(chunk))
}

fn collect_timestamped(
    read_fd: RawFd,
    mut output: RotatingLog,
    attach: Option<Arc<Mutex<Vec<UnixStream>>>>,
) {
    let mut pending: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8 * 1024];
    loop {
        match crate::syscalls::read_fd(read_fd, &mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let chunk = &buf[..n as usize];
                if append_log_bytes(&mut output, &mut pending, chunk).is_err() {
                    crate::syscalls::close(read_fd);
                    return;
                }
                if let Some(clients) = &attach {
                    broadcast(clients, chunk);
                }
            }
            Err(_) => break,
        }
    }
    if !pending.is_empty() {
        let _ = write_timestamped_line(&mut output, &pending);
    }
    crate::syscalls::close(read_fd);
}

/// Append workload bytes to the timestamped line buffer, flushing complete
/// lines and splitting an unterminated line once it reaches the memory bound.
fn append_log_bytes(
    output: &mut RotatingLog,
    pending: &mut Vec<u8>,
    bytes: &[u8],
) -> std::io::Result<()> {
    pending.extend_from_slice(bytes);
    loop {
        let scan_len = pending.len().min(MAX_LOG_RECORD_BYTES);
        if let Some(end) = pending[..scan_len].iter().position(|&byte| byte == b'\n') {
            write_timestamped_line(output, &pending[..=end])?;
            pending.drain(..=end);
            continue;
        }
        if pending.len() < MAX_LOG_RECORD_BYTES {
            return Ok(());
        }

        // Keep the on-disk record line-oriented so timestamp stripping and
        // time filters remain well-defined. The original bytes are unchanged;
        // only this synthetic record boundary is added.
        pending.insert(MAX_LOG_RECORD_BYTES, b'\n');
        write_timestamped_line(output, &pending[..=MAX_LOG_RECORD_BYTES])?;
        pending.drain(..=MAX_LOG_RECORD_BYTES);
    }
}

fn write_timestamped_line(output: &mut RotatingLog, line: &[u8]) -> std::io::Result<()> {
    let timestamp = state::now_rfc3339_nanos();
    output.write_record(timestamp.as_bytes(), line)
}

/// Reconcile one stale "running" record (reaper died): mark it exited and
/// reclaim its host-side resources (nft table, veth, cgroup, IPAM slot).
/// Returns true when the record changed.
pub fn reconcile_stale(store: &Store, st: &mut ContainerState) -> bool {
    // A terminal attempt may still belong to a live reaper waiting to retry.
    // Only the reaper itself may clear this marker; once it is gone, preserve
    // the last exit code but make the record terminal.
    if st.status == Status::Exited && st.restart_pending {
        if st.reaper_alive() {
            return false;
        }
        st.restart_pending = false;
        st.reaper_pid = None;
        st.reaper_start_time = None;
        return true;
    }
    if st.status != Status::Running || st.pid_alive() {
        return false;
    }
    // The workload can exit just before its reaper persists the restart
    // decision. A live reaper still owns this lifecycle record.
    if st.reaper_alive() {
        return false;
    }
    // The PID is gone but state still says running: the reaper was killed or
    // the host rebooted. Best-effort reclaim of everything the reaper would
    // have torn down.
    if let Some(veth) = st.veth.as_deref() {
        crate::network::teardown_named(&st.id, veth, st.table.as_deref());
    }
    let mut cgroup_reclaimed = true;
    if let Some(cg) = st.cgroup.as_deref() {
        let path = Path::new(cg);
        if crate::cgroup::CgroupV2::is_container_path(&st.id, path) {
            if path.exists() {
                st.metrics = Some(state::ContainerMetrics::from_cgroup_path(path));
            }
            if let Err(error) = terminate_and_remove_cgroup(&st.id, path) {
                eprintln!(
                    "zerun: warn: failed to reclaim cgroup {} for container {}: {error}",
                    path.display(),
                    st.id
                );
                cgroup_reclaimed = false;
            }
        } else {
            eprintln!(
                "zerun: warn: refusing to reclaim unexpected cgroup path {} for container {}",
                path.display(),
                st.id
            );
            cgroup_reclaimed = false;
        }
    }
    if st.net == "bridge" {
        crate::network::release_ip(store.run_root(), &st.id);
    }
    st.status = Status::Exited;
    st.paused = false;
    st.restart_pending = false;
    st.reaper_pid = None;
    st.reaper_start_time = None;
    st.exit_code = st.exit_code.or(Some(137)); // SIGKILL-ish default
    st.finished = Some(state::now_rfc3339());
    st.table = None;
    st.veth = None;
    if cgroup_reclaimed {
        st.cgroup = None;
    }
    // The per-run overlay may survive when the reaper died so the record can
    // still be committed/inspected; `rm` is the authoritative cleanup path.
    true
}

/// Reconcile a dead reaper and durably persist the resulting terminal state.
///
/// Callers must not silently discard the save error: until this write succeeds,
/// the filesystem still advertises the container as running and every later
/// lifecycle command may repeat resource cleanup or make the stale record
/// appear live.
pub fn reconcile_stale_and_save(store: &Store, st: &mut ContainerState) -> ZResult<bool> {
    if !reconcile_stale(store, st) {
        return Ok(false);
    }
    st.save(store)?;
    Ok(true)
}

/// After `stop`/`rm -f` has killed a container's PID: normally the live reaper
/// observes the death and persists "exited" itself within milliseconds. Wait a
/// short grace period for that write; when the reaper is gone too (crash), do
/// the reconcile in its place so no stale "running" record survives.
pub fn settle_exit(store: &Store, id: &str) -> ZResult<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        match ContainerState::load(store, id) {
            None => return Ok(()), // --rm already removed the record
            Some(st) if st.status != Status::Running && !st.restart_pending => return Ok(()),
            Some(_) => {}
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if let Some(mut st) = ContainerState::load(store, id) {
        if st.restart_pending || (st.status == Status::Running && !st.pid_alive()) {
            reconcile_stale_and_save(store, &mut st)?;
        }
    }
    Ok(())
}

/// Reclaim host-side resources for an exited container that still holds them
/// (used by `rm` on records whose reaper did not clean up).
pub fn reclaim_resources(store: &Store, st: &ContainerState) {
    if let Some(veth) = st.veth.as_deref() {
        crate::network::teardown_named(&st.id, veth, st.table.as_deref());
    }
    if let Some(cg) = st.cgroup.as_deref() {
        let path = Path::new(cg);
        if let Err(error) = terminate_and_remove_cgroup(&st.id, path) {
            eprintln!(
                "zerun: warn: failed to reclaim cgroup {} for container {}: {error}",
                path.display(),
                st.id
            );
        }
    }
    if st.net == "bridge" {
        crate::network::release_ip(store.run_root(), &st.id);
    }
}

/// Terminate any tasks still attached to a validated lifecycle cgroup before
/// removing it. A host PID namespace has no kernel-wide kill boundary, and an
/// exec worker can outlive the top-level workload even for private PID
/// namespaces. Keep the cgroup path in state when either step fails so a later
/// reconciliation can retry instead of orphaning the tasks.
fn terminate_and_remove_cgroup(id: &str, path: &Path) -> ZResult<()> {
    if path.exists() {
        let cgroup = crate::cgroup::CgroupV2::open_for_container(id, path)?;
        cgroup.kill_all()?;
    }
    crate::cgroup::CgroupV2::remove_for_container(id, path)
}

/// Write all of `buf` to `fd`, tolerating EINTR (best effort).
fn write_all(fd: RawFd, buf: &[u8]) -> ZResult<()> {
    crate::syscalls::write_all_fd(fd, buf)
}

#[cfg(test)]
mod attach_tests {
    use super::*;

    fn temp_log_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zerun-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn read_logs(active: &Path, max_files: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        for path in crate::logs::log_paths(active, max_files) {
            bytes.extend_from_slice(&std::fs::read(path).unwrap_or_default());
        }
        bytes
    }

    #[test]
    fn attach_data_frames_preserve_arbitrary_workload_bytes() {
        let (server, mut client) = UnixStream::pair().unwrap();
        let clients = Arc::new(Mutex::new(vec![server]));
        broadcast(&clients, b"exit=7\n");
        broadcast(&clients, b"no-newline");
        assert_eq!(
            read_attach_frame(&mut client).unwrap(),
            AttachFrame::Data(b"exit=7\n".to_vec())
        );
        assert_eq!(
            read_attach_frame(&mut client).unwrap(),
            AttachFrame::Data(b"no-newline".to_vec())
        );
    }

    #[test]
    fn attach_control_frame_carries_the_exit_status() {
        let (server, mut client) = UnixStream::pair().unwrap();
        let hub = AttachHub {
            clients: Arc::new(Mutex::new(vec![server])),
            sock_path: std::path::PathBuf::from("/nonexistent/zerun-test.sock"),
        };
        hub.close_all(7);
        assert_eq!(
            read_attach_frame(&mut client).unwrap(),
            AttachFrame::Exit(7)
        );
    }

    #[test]
    fn attach_reports_clean_eof_without_an_exit_frame() {
        let (server, mut client) = UnixStream::pair().unwrap();
        drop(server);
        assert_eq!(read_attach_frame(&mut client).unwrap(), AttachFrame::Eof);
    }

    #[test]
    fn attach_rejects_truncated_exit_frames() {
        let (mut server, mut client) = UnixStream::pair().unwrap();
        server.write_all(&0u32.to_be_bytes()).unwrap();
        server.write_all(&[0, 0]).unwrap();
        drop(server);
        assert_eq!(
            read_attach_frame(&mut client).unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn attach_rejects_oversized_frames() {
        let (mut server, mut client) = UnixStream::pair().unwrap();
        server
            .write_all(&(1024u32 * 1024 + 1).to_be_bytes())
            .unwrap();
        assert_eq!(
            read_attach_frame(&mut client).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn attach_registration_prunes_disconnected_clients_and_enforces_the_limit() {
        let mut clients = Vec::new();
        let mut peers = Vec::new();
        for _ in 0..MAX_ATTACH_CLIENTS {
            let (server, peer) = UnixStream::pair().unwrap();
            server.set_nonblocking(true).unwrap();
            assert!(register_attach_client(&mut clients, server));
            peers.push(peer);
        }
        assert_eq!(clients.len(), MAX_ATTACH_CLIENTS);

        let (server, _peer) = UnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        assert!(!register_attach_client(&mut clients, server));

        peers.remove(0);
        let (server, _peer) = UnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        assert!(register_attach_client(&mut clients, server));
        assert_eq!(clients.len(), MAX_ATTACH_CLIENTS);
    }

    #[test]
    fn rotating_log_keeps_the_configured_number_of_files() {
        let dir = temp_log_dir("rotate-log");
        let active = dir.join("console.log");
        std::fs::write(&active, b"").unwrap();
        let options = LogOptions {
            max_size: 24,
            max_files: 3,
        };
        let mut log = RotatingLog::open(&active, options).unwrap();
        for line in [b"first\n".as_slice(), b"second\n", b"third\n", b"fourth\n"] {
            log.write_record(b"2026-01-01T00:00:00.000000000Z", line)
                .unwrap();
        }
        drop(log);

        assert!(active.exists());
        assert!(dir.join("console.log.1").exists());
        assert!(dir.join("console.log.2").exists());
        assert!(!dir.join("console.log.3").exists());

        let retained = read_logs(&active, 3);
        assert!(!retained.windows(b"first".len()).any(|w| w == b"first"));
        assert!(retained.windows(b"second".len()).any(|w| w == b"second"));
        assert!(retained.windows(b"third".len()).any(|w| w == b"third"));
        assert!(retained.windows(b"fourth".len()).any(|w| w == b"fourth"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotating_log_can_disable_rotation() {
        let dir = temp_log_dir("rotate-disabled");
        let active = dir.join("console.log");
        std::fs::write(&active, b"").unwrap();
        let mut log = RotatingLog::open(
            &active,
            LogOptions {
                max_size: 0,
                max_files: 1,
            },
        )
        .unwrap();
        for line in [b"first\n".as_slice(), b"second\n", b"third\n"] {
            log.write_record(b"2026-01-01T00:00:00.000000000Z", line)
                .unwrap();
        }
        drop(log);

        let bytes = std::fs::read(&active).unwrap();
        assert!(bytes.windows(b"first".len()).any(|w| w == b"first"));
        assert!(bytes.windows(b"third".len()).any(|w| w == b"third"));
        assert!(!dir.join("console.log.1").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotating_log_with_one_file_keeps_only_the_active_file() {
        let dir = temp_log_dir("rotate-one");
        let active = dir.join("console.log");
        std::fs::write(&active, b"").unwrap();
        let mut log = RotatingLog::open(
            &active,
            LogOptions {
                max_size: 12,
                max_files: 1,
            },
        )
        .unwrap();
        for line in [b"first\n".as_slice(), b"second\n", b"third\n"] {
            log.write_record(b"2026-01-01T00:00:00.000000000Z", line)
                .unwrap();
        }
        drop(log);

        let bytes = std::fs::read(&active).unwrap();
        assert!(bytes.windows(b"third".len()).any(|w| w == b"third"));
        assert!(!bytes.windows(b"second".len()).any(|w| w == b"second"));
        assert!(!dir.join("console.log.1").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unterminated_console_lines_are_split_with_a_bounded_buffer() {
        let dir = temp_log_dir("bounded-line");
        let active = dir.join("console.log");
        std::fs::write(&active, b"").unwrap();
        let mut log = RotatingLog::open(
            &active,
            LogOptions {
                max_size: 0,
                max_files: 1,
            },
        )
        .unwrap();

        let payload = vec![b'x'; MAX_LOG_RECORD_BYTES * 2 + 17];
        let mut pending = Vec::new();
        append_log_bytes(&mut log, &mut pending, &payload).unwrap();
        assert_eq!(pending.len(), 17);
        write_timestamped_line(&mut log, &pending).unwrap();
        drop(log);

        let stored = std::fs::read(&active).unwrap();
        let mut expected = Vec::new();
        expected.extend(std::iter::repeat_n(b'x', MAX_LOG_RECORD_BYTES));
        expected.push(b'\n');
        expected.extend(std::iter::repeat_n(b'x', MAX_LOG_RECORD_BYTES));
        expected.push(b'\n');
        expected.extend(std::iter::repeat_n(b'x', 17));
        assert_eq!(crate::logs::strip_log_timestamps(&stored), expected);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn console_line_buffering_preserves_terminated_lines_and_the_final_partial_line() {
        let dir = temp_log_dir("normal-lines");
        let active = dir.join("console.log");
        std::fs::write(&active, b"").unwrap();
        let mut log = RotatingLog::open(
            &active,
            LogOptions {
                max_size: 0,
                max_files: 1,
            },
        )
        .unwrap();

        let payload = b"first\nsecond\npartial";
        let mut pending = Vec::new();
        append_log_bytes(&mut log, &mut pending, payload).unwrap();
        assert_eq!(pending, b"partial");
        write_timestamped_line(&mut log, &pending).unwrap();
        drop(log);

        let stored = std::fs::read(&active).unwrap();
        assert_eq!(crate::logs::strip_log_timestamps(&stored), payload);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_reconcile_persists_the_terminal_state() {
        let root = std::env::temp_dir().join(format!(
            "zerun-stale-reconcile-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let store = Store::at(root.join("data"), root.join("run"));
        store.ensure_dirs().unwrap();
        let id = "0123456789ab";
        let state = ContainerState {
            version: 1,
            id: id.to_string(),
            name: None,
            image: "rootfs:/tmp/rootfs".to_string(),
            pid: Some(i32::MAX),
            pid_start_time: None,
            reaper_pid: None,
            reaper_start_time: None,
            status: Status::Running,
            paused: false,
            exit_code: None,
            created: state::now_rfc3339(),
            started: Some(state::now_rfc3339()),
            finished: None,
            rootless: false,
            net: "none".to_string(),
            namespaces: Default::default(),
            ports: Vec::new(),
            port_protocols: None,
            port_ips: None,
            ip: None,
            cmd: vec!["/bin/sh".to_string()],
            env: Vec::new(),
            cwd: None,
            user: None,
            group_add: None,
            sysctls: std::collections::BTreeMap::new(),
            stop_signal: crate::signal::DEFAULT_STOP_SIGNAL,
            stop_timeout: crate::state::DEFAULT_STOP_TIMEOUT_SECS,
            restart_policy: crate::restart::RestartPolicy::No,
            restart_count: 0,
            restart_pending: false,
            healthcheck: None,
            health: None,
            capabilities: None,
            seccomp: Some(crate::seccomp::SeccompMode::Unconfined),
            ulimits: None,
            anonymous_volumes: Vec::new(),
            image_volumes: Vec::new(),
            log: String::new(),
            log_max_size: None,
            log_max_file: None,
            lower: None,
            rootfs: "/tmp/rootfs".to_string(),
            overlay: None,
            tmpfs_upper: false,
            labels: std::collections::BTreeMap::new(),
            launch_args: None,
            table: None,
            veth: None,
            cgroup: None,
            metrics: None,
        };
        state.save(&store).unwrap();

        let mut loaded = ContainerState::load(&store, id).unwrap();
        assert!(reconcile_stale_and_save(&store, &mut loaded).unwrap());
        let persisted = ContainerState::load(&store, id).unwrap();
        assert_eq!(persisted.status, Status::Exited);
        assert_eq!(persisted.exit_code, Some(137));
        assert!(persisted.finished.is_some());
        assert!(!persisted.pid_alive());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn started_state_persistence_requires_the_record_to_exist() {
        let root = std::env::temp_dir().join(format!(
            "zerun-started-state-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let store = Store::at(root.join("data"), root.join("run"));
        store.ensure_dirs().unwrap();
        let info = crate::namespace::StartedInfo {
            pid: std::process::id() as i32,
            pid_start_time: None,
            ip: None,
            table: None,
            veth: None,
            cgroup: None,
        };
        let error = persist_started_state(&store, "0123456789ab", &info).unwrap_err();
        assert!(error.to_string().contains("disappeared before start"));
        let _ = std::fs::remove_dir_all(&root);
    }
}
