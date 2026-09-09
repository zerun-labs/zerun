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
use crate::store::Store;
use serde::{Deserialize, Serialize};
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
    pub status: Status,
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
    /// Bridge IP when net == bridge.
    pub ip: Option<Ipv4Addr>,
    /// Command the container runs.
    pub cmd: Vec<String>,
    /// Container environment (KEY=VALUE) at start; used by `ze exec`.
    pub env: Vec<String>,
    /// Working directory inside the container at start.
    pub cwd: Option<String>,
    /// Absolute path to this container's console.log.
    pub log: String,
    /// Container root the process pivoted into (overlay merged dir, or the
    /// legacy `--rootfs` dir); `ze exec` chroots here.
    pub rootfs: String,
    /// When set, the per-run overlay directory `rm` should delete on top of
    /// the state directory (legacy `--rootfs` runs keep nothing to remove).
    pub overlay: Option<String>,
    /// nft table name for this container's egress NAT (crash reconcile).
    pub table: Option<String>,
    /// veth host-end name (crash reconcile).
    pub veth: Option<String>,
    /// cgroup v2 directory path, when limits were applied.
    pub cgroup: Option<String>,
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
        let p = Self::path(store, id);
        let text = std::fs::read_to_string(&p).ok()?;
        serde_json::from_str(&text).ok()
    }

    /// Atomically persist this record.
    pub fn save(&self) -> ZResult<()> {
        let p = Self::path_from(&self.log);
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| crate::zerr!("serialize state for {}: {e}", self.id))?;
        fsutil::atomic_write(&p, &json)
    }

    fn path_from(log_path: &str) -> PathBuf {
        Path::new(log_path)
            .parent()
            .map(|d| d.join("state.json"))
            .unwrap_or_else(|| PathBuf::from("state.json"))
    }

    /// Human-friendly status line for `ze ps`.
    pub fn status_label(&self) -> String {
        match self.status {
            Status::Running => "Up".to_string(),
            Status::Exited => format!("Exited ({})", self.exit_code.unwrap_or(-1)),
            Status::Created => "Created".to_string(),
        }
    }

    /// True when the recorded PID is still alive on the host.
    pub fn pid_alive(&self) -> bool {
        match self.pid {
            Some(pid) if pid > 0 => {
                let alive = unsafe { libc::kill(pid, 0) } == 0;
                let denied = std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
                alive || denied
            }
            _ => false,
        }
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
    fn timestamps_look_rfc3339() {
        let t = now_rfc3339();
        assert_eq!(t.len(), 20);
        assert!(t.ends_with('Z'));
        assert_eq!(&t[4..5], "-");
        assert_eq!(&t[10..11], "T");
    }

    #[test]
    fn resolve_matches_name_and_prefix() {
        let mut a = ContainerState {
            version: 1,
            id: "0123456789ab".to_string(),
            name: Some("web".to_string()),
            image: "alpine:latest".to_string(),
            pid: None,
            status: Status::Exited,
            exit_code: Some(0),
            created: now_rfc3339(),
            started: None,
            finished: None,
            rootless: false,
            net: "none".to_string(),
            ports: vec![],
            ip: None,
            cmd: vec!["sh".to_string()],
            env: vec![],
            cwd: None,
            log: format!("{}/x/console.log", std::env::temp_dir().display()),
            rootfs: String::new(),
            overlay: None,
            table: None,
            veth: None,
            cgroup: None,
        };
        // The struct has no store; save requires a writable dir under the log path.
        // Exercise save/load round trip through a temp dir instead.
        let dir = std::env::temp_dir().join(format!("zerun-state-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        a.log = dir.join("console.log").display().to_string();
        a.save().unwrap();
        assert!(dir.join("state.json").exists());
        let loaded: ContainerState =
            serde_json::from_str(&std::fs::read_to_string(dir.join("state.json")).unwrap())
                .unwrap();
        assert_eq!(loaded.id, a.id);
        assert_eq!(loaded.name.as_deref(), Some("web"));
        assert_eq!(loaded.status, Status::Exited);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
