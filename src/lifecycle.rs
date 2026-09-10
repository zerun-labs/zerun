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
use std::os::fd::RawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The detached reaper's whole job. Runs the container, persists state, then
/// returns the exit code (the caller `_exit`s). `overlay_dir` (if any) is
/// removed after the container exits; `started_w` carries the "0" (started)
/// or "1:<error>" signal back to the `run -d` CLI.
pub struct LogTarget<'a> {
    pub path: &'a Path,
    pub previous_fd: RawFd,
    pub options: LogOptions,
}

pub fn run_detached(
    store: Store,
    spec: RunSpec,
    container_fs: Option<ContainerFs>,
    remove_state: bool,
    started_w: RawFd,
    log: LogTarget<'_>,
) -> i32 {
    let id = spec.id.clone();
    // Replace inherited stdio with a timestamping collector before clone so
    // the container's real stdout/stderr are the collector's write ends.
    let mut captured_log = match CapturedLog::install(log.path, log.previous_fd, log.options) {
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
    let result = run_container_with_report(spec, |info| {
        // Persist "running" before releasing the CLI so `ze ps` never sees a
        // Created-but-alive container.
        if let Some(mut st) = ContainerState::load(&store, &id) {
            st.status = Status::Running;
            st.paused = false;
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
    let mut metrics = None;
    match result {
        Ok(exit) => {
            code = exit.code;
            metrics = exit.metrics;
        }
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

    // Final state: exited. Namespace capture already snapshotted metrics just
    // before cgroup cleanup; keep any older snapshot when unavailable.
    if let Some(mut st) = ContainerState::load(&store, &id) {
        st.metrics = metrics.or(st.metrics);
        st.status = Status::Exited;
        st.paused = false;
        st.exit_code = Some(code);
        st.finished = Some(state::now_rfc3339());
        let _ = st.save();
    }
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
        let dir = state::ContainerState::dir(&store, &id);
        fsutil::remove_dir_all_quiet(&dir);
    }
    code
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
        // the collector; the container inherits these write ends through clone.
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
        let written = file.metadata()?.len();
        Ok(Self {
            active: active.to_path_buf(),
            file,
            written,
            options,
        })
    }

    fn write_record(&mut self, timestamp: &[u8], line: &[u8]) -> std::io::Result<()> {
        let mut record =
            Vec::with_capacity(timestamp.len().saturating_add(1).saturating_add(line.len()));
        record.extend_from_slice(timestamp);
        record.push(b'\t');
        record.extend_from_slice(line);
        let record_len = record.len() as u64;
        if self.options.max_size > 0
            && self.written > 0
            && self.written.saturating_add(record_len) > self.options.max_size
        {
            self.rotate()?;
        }
        self.file.write_all(&record)?;
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
        let replacement = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
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
                for stream in listener.incoming() {
                    match stream {
                        Ok(s) => {
                            // Keep the collector non-blocking even if an
                            // attached client stops reading; such a client is
                            // dropped and can catch up with `zerun logs`.
                            let _ = s.set_nonblocking(true);
                            if let Ok(mut list) = worker_clients.lock() {
                                list.push(s);
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

/// Read one attach-socket frame. `None` means "container exited" and carries
/// the final status in the control payload.
pub fn read_attach_frame(stream: &mut UnixStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut prefix = [0u8; 4];
    stream.read_exact(&mut prefix)?;
    let len = u32::from_be_bytes(prefix);
    if len == 0 {
        let mut code = [0u8; 4];
        stream.read_exact(&mut code)?;
        return Ok(None);
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
    Ok(Some(chunk))
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
            Ok(n) => pending.extend_from_slice(&buf[..n as usize]),
            Err(_) => break,
        }
        while let Some(end) = pending.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = pending.drain(..=end).collect();
            if write_timestamped_line(&mut output, &line).is_err() {
                crate::syscalls::close(read_fd);
                return;
            }
            if let Some(clients) = &attach {
                broadcast(clients, &line);
            }
        }
    }
    if !pending.is_empty() {
        let _ = write_timestamped_line(&mut output, &pending);
        if let Some(clients) = &attach {
            broadcast(clients, &pending);
        }
    }
    crate::syscalls::close(read_fd);
}

fn write_timestamped_line(output: &mut RotatingLog, line: &[u8]) -> std::io::Result<()> {
    let timestamp = state::now_rfc3339_nanos();
    output.write_record(timestamp.as_bytes(), line)
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
    if let Some(veth) = st.veth.as_deref() {
        crate::network::teardown_named(veth, st.table.as_deref());
    }
    if let Some(cg) = st.cgroup.as_deref() {
        let path = Path::new(cg);
        if path.exists() {
            st.metrics = Some(state::ContainerMetrics::from_cgroup_path(path));
        }
        let _ = std::fs::remove_dir(path);
    }
    if st.net == "bridge" {
        crate::network::release_ip(store.run_root(), &st.id);
    }
    st.status = Status::Exited;
    st.paused = false;
    st.exit_code = st.exit_code.or(Some(137)); // SIGKILL-ish default
    st.finished = Some(state::now_rfc3339());
    st.table = None;
    st.veth = None;
    st.cgroup = None;
    // The per-run overlay may survive when the reaper died so the record can
    // still be committed/inspected; `rm` is the authoritative cleanup path.
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
    if let Some(veth) = st.veth.as_deref() {
        crate::network::teardown_named(veth, st.table.as_deref());
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
            Some(b"exit=7\n".to_vec())
        );
        assert_eq!(
            read_attach_frame(&mut client).unwrap(),
            Some(b"no-newline".to_vec())
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
        assert_eq!(read_attach_frame(&mut client).unwrap(), None);
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
}
