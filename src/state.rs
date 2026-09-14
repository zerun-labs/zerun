//! Per-container lifecycle state (M5): daemonless state lives on the
//! filesystem under `<run>/containers/<id>/`.
//!
//!   * `state.json` — one machine-readable record per *detached* container,
//!     written by the CLI at creation and updated by the reaper when the
//!     container starts and exits. `ps`/`stop`/`rm`/`logs`/`exec` read it.
//!   * `console.log` — captured stdout/stderr of a detached container
//!     (`ze logs`).
//!
//! Foreground runs are self-managed by their terminal CLI and keep no state;
//! lifecycle commands (`ps`/`stop`/...) therefore address detached
//! containers, like `docker run -d`.
use crate::error::ZResult;
use crate::fsutil;
use crate::seccomp::SeccompMode;
use crate::store::Store;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Runtime status of a detached container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Created,
    Running,
    Exited,
}

/// Cross-process lock covering one container's lifecycle mutations.
///
/// The lock lives outside the state directory so `rm` can safely unlink the
/// record without allowing a concurrent command to lock a replacement inode.
/// It is released explicitly rather than only on drop because `run_detached`
/// forks a long-lived reaper that inherits the descriptor.
pub struct ContainerOperationLock {
    file: File,
}

impl ContainerOperationLock {
    /// Try to reserve a container for a lifecycle mutation without waiting.
    ///
    /// Commands that mutate lifecycle state should fail fast when another
    /// command owns the container; silently queueing behind a long-running
    /// `start` can make the caller operate on stale state.
    pub fn try_acquire(store: &Store, id: &str) -> Result<Self, String> {
        let dir = store.run_root().join("locks");
        fsutil::mkdir_p(&dir).map_err(|e| e.to_string())?;
        let path = dir.join(format!("{id}.lock"));
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| format!("open container lock {}: {e}", path.display()))?;
        file.try_lock()
            .map_err(|e| format!("container {id} is busy with another lifecycle operation: {e}"))?;
        Ok(Self { file })
    }
}

impl Drop for ContainerOperationLock {
    fn drop(&mut self) {
        // Explicit unlock avoids leaving the inherited reaper descriptor
        // holding the lock after the foreground CLI returns.
        let _ = self.file.unlock();
    }
}

/// Final cgroup metrics captured by the reaper before cleanup.
///
/// Running containers are read directly from the live cgroup; exited
/// containers keep this snapshot so `stats` remains useful after the cgroup
/// directory is removed. Fields are optional because older kernels may not
/// expose every control file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerMetrics {
    /// Current or final memory usage in bytes (`memory.current`).
    pub memory_bytes: Option<u64>,
    /// Highest observed memory usage in bytes (`memory.peak`).
    pub memory_peak_bytes: Option<u64>,
    /// Cumulative CPU time in microseconds (`cpu.stat usage_usec`).
    pub cpu_usage_usec: Option<u64>,
    /// PIDs observed at capture time (`pids.current`).
    pub pids: Option<u64>,
    /// Sum of `rbps` values across devices (`io.stat`).
    pub io_read_bytes: Option<u64>,
    /// Sum of `wbps` values across devices (`io.stat`).
    pub io_write_bytes: Option<u64>,
}

/// Parse a cgroup v2 key/value stat file. Missing files yield `None`.
impl ContainerMetrics {
    pub fn from_cgroup_path(path: &Path) -> Self {
        let memory_bytes = read_u64(&path.join("memory.current"));
        let memory_peak_bytes = read_u64(&path.join("memory.peak"));
        let cpu_stat = std::fs::read_to_string(path.join("cpu.stat")).ok();
        let cpu_usage_usec = cpu_stat
            .as_deref()
            .and_then(|text| stat_value(text, "usage_usec"));
        let pids = read_u64(&path.join("pids.current"));
        let io_stat = std::fs::read_to_string(path.join("io.stat")).ok();
        let (io_read_bytes, io_write_bytes) =
            io_stat.as_deref().map(io_bytes).unwrap_or((None, None));
        Self {
            memory_bytes,
            memory_peak_bytes,
            cpu_usage_usec,
            pids,
            io_read_bytes,
            io_write_bytes,
        }
    }
}

fn read_u64(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
}

/// Extract the unsigned value for `key` from whitespace-separated stat lines.
fn stat_value(text: &str, key: &str) -> Option<u64> {
    let mut fields = text.split_whitespace();
    while let (Some(k), Some(v)) = (fields.next(), fields.next()) {
        if k == key {
            return v.parse::<u64>().ok();
        }
    }
    None
}

/// Aggregate `io.stat` byte counters across all listed devices.
///
/// Each line is `<MAJOR:MINOR> key=value...`; parse line-by-line so the device
/// identifier does not become a value in a flat key/value stream.
fn io_bytes(text: &str) -> (Option<u64>, Option<u64>) {
    let mut read_bytes = 0_u64;
    let mut write_bytes = 0_u64;
    let mut saw_read = false;
    let mut saw_write = false;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        // The first token is the device; the remaining tokens are key/value
        // pairs such as `rbps=1024` or separate `rbps 1024` forms.
        if fields.next().is_none() {
            continue;
        }
        while let Some(token) = fields.next() {
            // The kernel emits `key=value`; also accept `key value` for tests
            // and hand-written fixtures.
            let (key, value) = if let Some(pair) = token.split_once('=') {
                pair
            } else {
                let Some(value) = fields.next() else { break };
                (token, value)
            };
            let Ok(value) = value.parse::<u64>() else {
                continue;
            };
            match key {
                "rbps" => {
                    read_bytes = read_bytes.saturating_add(value);
                    saw_read = true;
                }
                "wbps" => {
                    write_bytes = write_bytes.saturating_add(value);
                    saw_write = true;
                }
                _ => {}
            }
        }
    }
    (
        saw_read.then_some(read_bytes),
        saw_write.then_some(write_bytes),
    )
}

/// Persistent per-container record (versioned for future migrations).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerState {
    /// Schema version (currently 1).
    pub version: u32,
    pub id: String,
    /// User-assigned name (`--name`), if any.
    pub name: Option<String>,
    /// Image reference ("alpine:latest") or rootfs path for legacy runs.
    pub image: String,
    /// Host-side PID of the container's PID 1 while running.
    pub pid: Option<i32>,
    /// `/proc/<pid>/stat` starttime in clock ticks, used to detect PID reuse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid_start_time: Option<u64>,
    pub status: Status,
    /// True while the detached container's cgroup freezer is active.
    #[serde(default)]
    pub paused: bool,
    pub exit_code: Option<i32>,
    /// RFC3339 timestamps.
    pub created: String,
    pub started: Option<String>,
    pub finished: Option<String>,
    pub rootless: bool,
    /// "none" | "host" | "bridge".
    pub net: String,
    /// Published ports (host, container).
    pub ports: Vec<(u16, u16)>,
    /// Transport for each port (`tcp`/`udp`). Older records are TCP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_protocols: Option<Vec<String>>,
    /// Host bind address for each port. Older records bind 0.0.0.0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_ips: Option<Vec<String>>,
    /// Bridge IP when net == bridge.
    pub ip: Option<Ipv4Addr>,
    /// Command the container runs.
    pub cmd: Vec<String>,
    /// Container environment (KEY=VALUE) at start; used by `ze exec`.
    pub env: Vec<String>,
    /// Working directory inside the container at start.
    pub cwd: Option<String>,
    /// Container user (`--user` or the image `config.User`) applied before
    /// exec; `zerun exec` re-applies it. None = root.
    #[serde(default)]
    pub user: Option<String>,
    /// Exact capability set left for the workload. None = legacy record using
    /// the secure default set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    /// Seccomp policy applied to the workload. None = legacy record using the
    /// default deny-by-default profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seccomp: Option<SeccompMode>,
    /// Canonical absolute path to this container's console.log. Runtime code
    /// derives it from the store and id; the field remains serialized for
    /// compatibility and inspection.
    pub log: String,
    /// Rotation threshold for the console log. None = legacy/unbounded record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_max_size: Option<u64>,
    /// Total retained console files, including the active one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_max_file: Option<usize>,
    /// Read-only lower rootfs used by this container (including direct
    /// `--no-overlay` runs). `None` for legacy records. Required to resume a
    /// stopped container without resolving or pulling the image again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lower: Option<String>,
    /// Container root the process pivoted into (overlay merged dir, or the
    /// legacy `--rootfs` dir); `ze exec` chroots here.
    pub rootfs: String,
    /// When set, the per-run overlay directory `rm` should delete on top of
    /// the state directory (legacy `--rootfs` runs keep nothing to remove).
    pub overlay: Option<String>,
    /// True when the writable layer was ephemeral tmpfs (`--tmpfs-upper`).
    #[serde(default)]
    pub tmpfs_upper: bool,
    /// Operator/image labels (KEY=VALUE). Older records have none.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Canonical `zerun run` arguments (without the leading `run`) captured
    /// for detached containers. Older v1 records have no value and cannot be
    /// restarted directly.
    #[serde(default)]
    pub launch_args: Option<Vec<String>>,
    /// nft table name for this container's egress NAT (crash reconcile).
    pub table: Option<String>,
    /// veth host-end name (crash reconcile).
    pub veth: Option<String>,
    /// cgroup v2 directory path, when limits were applied.
    pub cgroup: Option<String>,
    /// Final metrics captured before cgroup cleanup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<ContainerMetrics>,
}

impl ContainerState {
    /// Path of `<run>/containers/<id>/state.json`.
    pub fn path(store: &Store, id: &str) -> PathBuf {
        store
            .run_root()
            .join("containers")
            .join(id)
            .join("state.json")
    }

    pub fn dir(store: &Store, id: &str) -> PathBuf {
        store.run_root().join("containers").join(id)
    }

    /// Load the state of one container id (exact match).
    pub fn load(store: &Store, id: &str) -> Option<ContainerState> {
        // `load` is also reached by CLI arguments through `resolve`; never
        // allow an arbitrary path component to escape `containers/`.
        if !valid_id(id) {
            return None;
        }
        let p = Self::path(store, id);
        let text = std::fs::read_to_string(&p).ok()?;
        let mut state: ContainerState = serde_json::from_str(&text).ok()?;
        // The directory name is the record's identity. Reject a JSON payload
        // that claims another id rather than letting metadata redirect later
        // lifecycle operations.
        if state.id != id || !valid_id(&state.id) {
            return None;
        }
        state.log = Self::log_path(store, id).display().to_string();
        Some(state)
    }

    /// Canonical console-log path for this container.
    pub fn log_path(store: &Store, id: &str) -> PathBuf {
        Self::dir(store, id).join("console.log")
    }

    /// Canonical console-log path for this loaded record.
    pub fn log_path_for(&self, store: &Store) -> PathBuf {
        Self::log_path(store, &self.id)
    }

    /// Atomically persist this record at the store-owned canonical path.
    ///
    /// Never derive the state-file location from the serialized `log` field:
    /// that field is persisted metadata and must not be able to redirect a
    /// lifecycle update outside `<run>/containers/<id>/`.
    pub fn save(&self, store: &Store) -> ZResult<()> {
        if !valid_id(&self.id) {
            return Err(crate::zerr!("invalid container id '{}'", self.id));
        }
        let p = Self::path(store, &self.id);
        let mut persisted = self.clone();
        persisted.log = Self::log_path_for(self, store).display().to_string();
        let json = serde_json::to_vec_pretty(&persisted)
            .map_err(|e| crate::zerr!("serialize state for {}: {e}", self.id))?;
        let parent = p
            .parent()
            .ok_or_else(|| crate::zerr!("state path has no parent: {}", p.display()))?;
        // State includes the resolved environment and command line, which can
        // contain credentials or other operator-provided secrets.
        fsutil::mkdir_p_mode(parent, 0o700)?;
        fsutil::atomic_write_mode(&p, &json, 0o600)
    }

    /// Human-friendly status line for `ze ps`.
    pub fn status_label(&self) -> String {
        match self.status {
            Status::Running if self.paused => "Up (Paused)".to_string(),
            Status::Running => "Up".to_string(),
            Status::Exited => format!("Exited ({})", self.exit_code.unwrap_or(-1)),
            Status::Created => "Created".to_string(),
        }
    }

    /// True when the recorded PID is still alive on the host and, for new
    /// records, is the same process that was originally started. Older state
    /// files without `pid_start_time` retain the historical kill(2)-only
    /// fallback for backward compatibility.
    pub fn pid_alive(&self) -> bool {
        let Some(pid) = self.pid.filter(|pid| *pid > 0) else {
            return false;
        };
        let alive = unsafe { libc::kill(pid, 0) } == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
        if !alive {
            return false;
        }
        self.pid_start_time
            .is_none_or(|expected| crate::procinfo::process_start_time(pid) == Some(expected))
    }
}

/// ISO-8601-ish timestamp for state records.
pub fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // RFC3339 without sub-second precision is enough for display/sorting.
    let days = secs / 86400;
    let rem = secs % 86400;
    let (y, m, d) = civil_from_days(days as i64);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// RFC3339 timestamp with nanosecond precision for captured log lines.
///
/// Log timestamps must identify individual writes; second precision can make
/// an entire burst of output look simultaneous and reorder ambiguously.
pub fn now_rfc3339_nanos() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let days = (d.as_secs() / 86400) as i64;
    let rem = d.as_secs() % 86400;
    let (y, m, day) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{day:02}T{:02}:{:02}:{:02}.{:09}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
        d.subsec_nanos()
    )
}

/// Howard Hinnant's civil_from_days algorithm (days since 1970-01-01).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Docker-compatible container-name validation:
/// `[a-zA-Z0-9][a-zA-Z0-9_.-]*`, 1..=128 characters.
///
/// Names are addressable on the CLI (`ps`/`logs`/`rename`), so rejecting
/// shell-hostile characters at creation keeps every consumer predictable.
pub fn valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// Container IDs are generated as hexadecimal strings. Restricting exact
/// state-file lookup to this alphabet prevents `../` and absolute-path input
/// from turning a lifecycle command into an arbitrary file read.
fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Resolve a user-supplied container argument (`<id>`/`<id-prefix>`/`<name>`)
/// against every state record.
///
/// Returns the matching state or a descriptive error when zero or multiple
/// records match.
pub fn resolve(store: &Store, arg: &str) -> Result<ContainerState, String> {
    // Exact id first.
    if let Some(s) = ContainerState::load(store, arg) {
        return Ok(s);
    }
    let all = list(store);
    // Name match (exact).
    if let Some(s) = all.iter().find(|s| s.name.as_deref() == Some(arg)) {
        return Ok(s.clone());
    }
    // Id-prefix match (docker semantics: unambiguous shortest prefix).
    let prefixed: Vec<&ContainerState> = all.iter().filter(|s| s.id.starts_with(arg)).collect();
    match prefixed.len() {
        1 => Ok(prefixed[0].clone()),
        0 => Err(format!("No such container: {arg}")),
        _ => Err(format!(
            "container id {arg} is ambiguous ({} matches)",
            prefixed.len()
        )),
    }
}

/// Every state record, newest first.
pub fn list(store: &Store) -> Vec<ContainerState> {
    let mut out = Vec::new();
    let dir = store.run_root().join("containers");
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return out;
    };
    for entry in rd.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        if let Some(s) = ContainerState::load(store, &entry.file_name().to_string_lossy()) {
            out.push(s);
        }
    }
    out.sort_by(|a, b| b.created.cmp(&a.created));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_timestamp_has_nanosecond_precision() {
        let ts = now_rfc3339_nanos();
        assert_eq!(ts.len(), 30);
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.as_bytes()[10], b'T');
        assert_eq!(ts.as_bytes()[19], b'.');
    }

    #[test]
    fn timestamps_look_rfc3339() {
        let t = now_rfc3339();
        assert_eq!(t.len(), 20);
        assert!(t.ends_with('Z'));
        assert_eq!(&t[4..5], "-");
        assert_eq!(&t[10..11], "T");
    }

    #[test]
    fn reads_metrics_from_cgroup_files() {
        let dir = std::env::temp_dir().join(format!(
            "zerun-cgroup-metrics-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("memory.current"), b"4096\n").unwrap();
        std::fs::write(dir.join("memory.peak"), b"8192\n").unwrap();
        std::fs::write(dir.join("pids.current"), b"3\n").unwrap();
        std::fs::write(
            dir.join("cpu.stat"),
            b"usage_usec 123456\nuser_usec 1000\nsystem_usec 2000\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("io.stat"),
            b"8:0 rbps=1024 wbps=128 riops=1 wiops=2\n8:16 rbps=256 wbps=64 riops=3 wiops=4\n",
        )
        .unwrap();
        let m = ContainerMetrics::from_cgroup_path(&dir);
        assert_eq!(m.memory_bytes, Some(4096));
        assert_eq!(m.memory_peak_bytes, Some(8192));
        assert_eq!(m.cpu_usage_usec, Some(123456));
        assert_eq!(m.pids, Some(3));
        assert_eq!(m.io_read_bytes, Some(1280));
        assert_eq!(m.io_write_bytes, Some(192));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stat_values_tolerate_missing_or_malformed_fields() {
        assert_eq!(stat_value("usage_usec abc\nother 3", "other"), Some(3));
        assert_eq!(stat_value("usage_usec x", "usage_usec"), None);
        assert_eq!(stat_value("other 1", "usage_usec"), None);
        let (read, write) = io_bytes("8:0 rbps notanumber wbps 10\n8:16 rbps=2 wbps=3");
        assert_eq!(read, Some(2));
        // The malformed rbps contributes no aggregate.
        assert_eq!(write, Some(13));
        assert_eq!(io_bytes(""), (None, None));
    }

    #[test]
    fn pid_start_time_prevents_pid_reuse_false_positive() {
        let mut state = ContainerState {
            version: 1,
            id: "pid-check".to_string(),
            name: None,
            image: "alpine".to_string(),
            pid: Some(std::process::id() as i32),
            pid_start_time: crate::procinfo::process_start_time(std::process::id() as i32),
            status: Status::Running,
            paused: false,
            exit_code: None,
            created: now_rfc3339(),
            started: Some(now_rfc3339()),
            finished: None,
            rootless: false,
            net: "none".to_string(),
            ports: vec![],
            port_protocols: None,
            port_ips: None,
            ip: None,
            cmd: vec![],
            env: vec![],
            cwd: None,
            user: None,
            capabilities: None,
            seccomp: None,
            log: String::new(),
            log_max_size: None,
            log_max_file: None,
            lower: None,
            rootfs: String::new(),
            overlay: None,
            tmpfs_upper: false,
            labels: BTreeMap::new(),
            launch_args: None,
            table: None,
            veth: None,
            cgroup: None,
            metrics: None,
        };
        assert!(state.pid_alive());
        state.pid_start_time = state.pid_start_time.map(|start| start.saturating_add(1));
        assert!(!state.pid_alive());
    }

    #[test]
    fn exact_state_lookup_rejects_path_traversal() {
        assert!(valid_id("0123456789abcdef"));
        assert!(valid_id(&"a".repeat(64)));
        assert!(!valid_id(""));
        assert!(!valid_id("../outside"));
        assert!(!valid_id("/absolute"));
        assert!(!valid_id(&"f".repeat(65)));

        let root = std::env::temp_dir().join(format!(
            "zerun-state-path-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let store = Store::at(root.join("data"), root.join("run"));
        store.ensure_dirs().unwrap();
        assert!(ContainerState::load(&store, "../state").is_none());
        assert!(ContainerState::load(&store, "/tmp/state").is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn container_name_validation() {
        assert!(valid_name("web"));
        assert!(valid_name("a1._-x"));
        assert!(valid_name("0"));
        assert!(valid_name(&"x".repeat(128)));
        assert!(!valid_name(""));
        assert!(!valid_name("-lead"));
        assert!(!valid_name(".dot"));
        assert!(!valid_name("has space"));
        assert!(!valid_name("uni\u{2026}code"));
        assert!(!valid_name(&"x".repeat(129)));
    }

    #[test]
    fn resolve_matches_name_and_prefix() {
        let mut a = ContainerState {
            version: 1,
            id: "0123456789ab".to_string(),
            name: Some("web".to_string()),
            image: "alpine:latest".to_string(),
            pid: None,
            pid_start_time: None,
            status: Status::Exited,
            paused: false,
            exit_code: Some(0),
            created: now_rfc3339(),
            started: None,
            finished: None,
            rootless: false,
            net: "none".to_string(),
            ports: vec![],
            port_protocols: None,
            port_ips: None,
            ip: None,
            cmd: vec!["sh".to_string()],
            env: vec![],
            cwd: None,
            user: None,
            capabilities: Some(vec!["CAP_NET_RAW".to_string()]),
            seccomp: Some(SeccompMode::Unconfined),
            log: format!("{}/x/console.log", std::env::temp_dir().display()),
            log_max_size: None,
            log_max_file: None,
            lower: Some("/tmp/lower".to_string()),
            rootfs: String::new(),
            overlay: None,
            tmpfs_upper: false,
            labels: BTreeMap::new(),
            launch_args: None,
            table: None,
            veth: None,
            cgroup: None,
            metrics: None,
        };
        let dir = std::env::temp_dir().join(format!("zerun-state-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::at(dir.join("data"), dir.join("run"));
        store.ensure_dirs().unwrap();
        // A persisted log path must not be able to redirect state writes.
        a.log = dir
            .join("attacker")
            .join("console.log")
            .display()
            .to_string();
        a.save(&store).unwrap();
        let state_path = ContainerState::path(&store, &a.id);
        assert!(state_path.exists());
        assert!(!dir.join("attacker/state.json").exists());
        let loaded: ContainerState =
            serde_json::from_str::<ContainerState>(&std::fs::read_to_string(&state_path).unwrap())
                .unwrap();
        assert_eq!(loaded.id, a.id);
        assert_eq!(loaded.name.as_deref(), Some("web"));
        assert_eq!(loaded.status, Status::Exited);
        assert_eq!(
            loaded.capabilities.as_deref(),
            Some(&["CAP_NET_RAW".to_string()][..])
        );
        assert_eq!(loaded.seccomp, Some(SeccompMode::Unconfined));
        assert_eq!(loaded.lower.as_deref(), Some("/tmp/lower"));
        assert_eq!(
            loaded.log,
            ContainerState::log_path_for(&loaded, &store)
                .display()
                .to_string()
        );

        let mut tampered: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        tampered["id"] = serde_json::Value::String("fedcba987654".to_string());
        std::fs::write(&state_path, serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert!(ContainerState::load(&store, &a.id).is_none());

        let mut invalid = a.clone();
        invalid.id = "../outside".to_string();
        assert!(invalid.save(&store).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn container_operation_lock_is_exclusive_until_dropped() {
        let root = std::env::temp_dir().join(format!(
            "zerun-state-lock-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let store = Store::at(root.join("data"), root.join("run"));
        store.ensure_dirs().unwrap();

        let first = ContainerOperationLock::try_acquire(&store, "abc123").unwrap();
        assert!(ContainerOperationLock::try_acquire(&store, "abc123").is_err());
        drop(first);
        assert!(ContainerOperationLock::try_acquire(&store, "abc123").is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }
}
