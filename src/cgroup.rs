//! Resource constraints: cgroups v2.
//!
//! Implements the direct cgroupfs driver (mkdir under the unified hierarchy).
//! Besides hard limits it applies `memory.high` (soft reservation) and
//! `memory.oom.group` for all-at-once OOM behavior. A systemd-scope driver and
//! a cgroups v1 fallback belong to later milestones.
use crate::error::ZResult;
use crate::trace;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Default, Clone)]
pub struct ResourceLimits {
    /// Raw size strings such as "64M", "512m", "1G"; None means no limit.
    pub memory: Option<String>,
    /// Soft memory reservation written to cgroups v2 `memory.high`.
    pub memory_reservation: Option<String>,
    /// Total memory+swap ceiling. It is converted to the swap-only cgroup v2
    /// `memory.swap.max` value; `-1` means unlimited. When `memory.max` is set
    /// without this field, swap is capped at the memory limit.
    pub memory_swap: Option<i64>,
    /// CPU cores (fractional), e.g. 0.5 -> cpu.max "50000 100000".
    pub cpus: Option<f64>,
    /// Docker-compatible v1 CPU shares, translated to cgroup v2 `cpu.weight`.
    pub cpu_shares: Option<u64>,
    /// CPU list bound to `cpuset.cpus`, e.g. "0-3" or "0,2".
    pub cpuset_cpus: Option<String>,
    /// Memory-node list bound to `cpuset.mems`, e.g. "0".
    pub cpuset_mems: Option<String>,
    /// Process count limit pids.max (default suggestion for low-end hosts: 256).
    pub pids: Option<i64>,
    /// Block I/O limits for cgroups v2 `io.max`, grouped by device on write.
    pub io: Vec<IoLimit>,
    /// Kill the whole cgroup (not one task) on OOM via `memory.oom.group`.
    pub oom_group: bool,
}

/// One device's I/O ceilings. `None` means "leave the kernel default".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IoLimit {
    /// Canonical `MAJOR:MINOR` form accepted by `io.max`.
    pub device: String,
    pub read_bps: Option<u64>,
    pub write_bps: Option<u64>,
    pub read_iops: Option<u64>,
    pub write_iops: Option<u64>,
}

pub struct CgroupV2 {
    path: PathBuf,
    /// Newly created cgroups are owned by this handle and are cleaned up on
    /// drop. Handles returned by `open` borrow an existing lifecycle cgroup.
    cleanup_on_drop: bool,
}

impl CgroupV2 {
    /// Return the cgroup path owned by Zerun for one container id.
    ///
    /// Lifecycle state may be edited or corrupted independently of cgroupfs,
    /// so callers must use this authority when opening or removing a cgroup
    /// instead of trusting a serialized path.
    pub fn container_path(id: &str) -> ZResult<PathBuf> {
        validate_container_id(id)?;
        Ok(detect_cgroup2_root()?.join("zerun").join(id))
    }

    /// Open a lifecycle cgroup only when its persisted path is exactly the
    /// path Zerun derives for the same container id.
    pub fn open_for_container(id: &str, persisted: &Path) -> ZResult<Self> {
        let expected = Self::container_path(id)?;
        if persisted != expected {
            return Err(crate::zerr!(
                "refusing cgroup path {} for container {} (expected {})",
                persisted.display(),
                id,
                expected.display()
            ));
        }
        Self::open(&expected)
    }

    /// Check whether a persisted path is the cgroup Zerun owns for `id`.
    /// This is intentionally best effort: a missing cgroup hierarchy means
    /// there is no safe path to inspect or remove.
    pub fn is_container_path(id: &str, persisted: &Path) -> bool {
        Self::container_path(id).is_ok_and(|expected| expected == persisted)
    }

    /// Remove a lifecycle cgroup only when its persisted path is exactly the
    /// path derived from the validated container id. Missing leaves are
    /// already reconciled; an occupied leaf returns the kernel error so the
    /// caller can retain the path and retry instead of losing the cleanup
    /// authority from state.
    pub fn remove_for_container(id: &str, persisted: &Path) -> ZResult<()> {
        let expected = Self::container_path(id)?;
        if persisted != expected {
            return Err(crate::zerr!(
                "refusing to remove cgroup {} for container {} (expected {})",
                persisted.display(),
                id,
                expected.display()
            ));
        }
        match fs::remove_dir(&expected) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(crate::zerr!(
                    "remove cgroup {} failed: {e}",
                    expected.display()
                ))
            }
        }
        // The parent is shared by all containers; remove it only when empty.
        if let Some(parent) = expected.parent() {
            let _ = fs::remove_dir(parent);
        }
        Ok(())
    }

    /// Create the sub-hierarchy <cgroup2>/zerun/<id>.
    ///
    /// cgroups v2 requires every controller to be enabled in the parent's
    /// subtree_control before the leaf gets the corresponding control files, so
    /// the intermediate <cgroup2>/zerun level enables cpu/memory/pids on demand.
    pub fn create(id: &str, limits: &ResourceLimits) -> ZResult<Self> {
        validate_container_id(id)?;
        if limits.memory.is_none() && limits.memory_swap.is_some_and(|swap| swap >= 0) {
            return Err(crate::zerr!(
                "a finite memory-swap ceiling requires --memory"
            ));
        }
        let root = detect_cgroup2_root()?;
        let parent = root.join("zerun");
        let path = parent.join(id);
        fs::create_dir_all(&parent).map_err(|e| {
            crate::zerr!(
                "create cgroup parent {} failed: {e}. Hint: root or a delegated cgroup v2 subtree is required",
                parent.display()
            )
        })?;
        // Do not use create_dir_all for the leaf: reusing an existing id could
        // attach a new workload to another container's live cgroup after an id
        // collision or stale state record.
        fs::create_dir(&path).map_err(|e| {
            let detail = if e.kind() == std::io::ErrorKind::AlreadyExists {
                format!("container cgroup already exists at {}", path.display())
            } else {
                format!("create cgroup {} failed: {e}", path.display())
            };
            crate::zerr!("{detail}. Hint: root or a delegated cgroup v2 subtree is required")
        })?;
        // Construct the owning handle before the remaining setup steps so a
        // controller or limit failure cannot leave the empty leaf behind.
        let cg = CgroupV2 {
            path,
            cleanup_on_drop: true,
        };
        enable_controllers(&parent, &["memory", "cpu", "pids", "io", "cpuset"])?;
        cg.apply_limits(&parent, limits)?;
        trace::mark("parent:cgroup:configured");
        Ok(cg)
    }

    /// Open an existing cgroup directory (for `zerun update`).
    pub fn open(path: &Path) -> ZResult<Self> {
        if !path.is_dir() {
            return Err(crate::zerr!("cgroup {} does not exist", path.display()));
        }
        Ok(CgroupV2 {
            path: path.to_path_buf(),
            cleanup_on_drop: false,
        })
    }

    /// Write every provided limit onto this cgroup (shared by create and
    /// `zerun update`). All user-provided values and required controllers are
    /// validated before the first cgroup file is changed, so a malformed later
    /// option cannot leave an earlier limit partially applied.
    pub fn apply_limits(&self, parent: &Path, limits: &ResourceLimits) -> ZResult<()> {
        let current_memory =
            if limits.memory.is_none() && limits.memory_swap.is_some_and(|swap| swap >= 0) {
                let value = fs::read_to_string(self.path.join("memory.max"))
                    .map_err(|e| crate::zerr!("read current memory.max failed: {e}"))?;
                Some(value.trim().parse::<u64>().map_err(|_| {
                    crate::zerr!("finite memory-swap requires a finite current memory.max")
                })?)
            } else {
                None
            };

        if limits.memory.is_some()
            || limits.memory_reservation.is_some()
            || limits.memory_swap.is_some()
            || limits.oom_group
        {
            require_controller(parent, "memory")?;
        }
        if limits.cpus.is_some() || limits.cpu_shares.is_some() {
            require_controller(parent, "cpu")?;
        }
        if limits.pids.is_some() {
            require_controller(parent, "pids")?;
        }
        if limits.cpuset_cpus.is_some() || limits.cpuset_mems.is_some() {
            require_controller(parent, "cpuset")?;
        }

        // io.max is stateful: writing a subset of devices or dimensions would
        // reset every omitted device/dimension to "max". Read the kernel view
        // first and merge updates so a live `update` changes only what the
        // operator named.
        let current_io = if limits.io.is_empty() {
            None
        } else {
            require_controller(parent, "io")?;
            Some(
                fs::read_to_string(self.path.join("io.max"))
                    .map_err(|e| crate::zerr!("read current io.max failed: {e}"))?,
            )
        };
        let writes = plan_limit_writes(limits, current_memory, current_io.as_deref())?;
        for (file, value) in writes {
            self.write(file, value)?;
        }
        Ok(())
    }

    /// Absolute path of this cgroup directory (used by lifecycle state).
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn write(&self, file: &str, value: String) -> ZResult<()> {
        let p = self.path.join(file);
        fs::write(&p, value.as_bytes())
            .map_err(|e| crate::zerr!("write {} = {} failed: {e}", p.display(), value))
    }

    /// Write the parked workload PID into cgroup.procs immediately after the
    /// supervisor forks it. The worker may already have exited, in which case
    /// `ESRCH` is harmless; a missing cgroup is a launch failure because the
    /// worker must not run without the limits this handle represents.
    pub fn attach(&self, pid: i32) -> ZResult<()> {
        match fs::write(self.path.join("cgroup.procs"), pid.to_string()) {
            Ok(_) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(()),
            Err(e) => Err(crate::zerr!(
                "write {} = {} failed: {e}",
                self.path.join("cgroup.procs").display(),
                pid
            )),
        }
    }

    /// Freeze or thaw every task in this cgroup (cgroups v2 freezer).
    ///
    /// The kernel reports completion through `cgroup.events`; wait for the
    /// requested state so `pause` does not return while a workload is still
    /// consuming CPU.
    pub fn freeze(&self, frozen: bool) -> ZResult<()> {
        self.set_freeze(frozen)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if read_frozen(&self.path) == Some(frozen) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(crate::zerr!(
                    "timed out waiting for cgroup {} to {}",
                    self.path.display(),
                    if frozen { "freeze" } else { "thaw" }
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn set_freeze(&self, frozen: bool) -> ZResult<()> {
        self.write("cgroup.freeze", if frozen { "1" } else { "0" }.to_string())
    }

    /// SIGKILL every task in this cgroup and wait for the kernel to report it
    /// empty. `cgroup.kill` is atomic and prevents new forks; kernels before
    /// its introduction fall back to freezing the cgroup before enumerating
    /// `cgroup.procs`, which closes the same fork race.
    ///
    /// A task stuck in uninterruptible sleep can outlive the bounded wait. In
    /// that case the caller must retain the cgroup path for a later retry.
    pub fn kill_all(&self) -> ZResult<()> {
        const KILL_WAIT: Duration = Duration::from_secs(2);
        // A missing leaf means there is nothing left to terminate. This is a
        // normal outcome when reconciliation races an already-finished cleanup.
        if !self.path.exists() {
            return Ok(());
        }
        let kill_path = self.path.join("cgroup.kill");
        // Check first instead of relying on ENOENT: a diagnostic directory (or
        // a future non-cgroupfs backend used by tests) would let fs::write
        // create a regular file where cgroupfs reports the control file absent.
        if kill_path.exists() {
            match fs::write(&kill_path, b"1") {
                Ok(()) => return self.wait_populated(false, KILL_WAIT),
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                    // The leaf or control file was removed concurrently.
                    if !self.path.exists() {
                        return Ok(());
                    }
                }
                Err(error) => {
                    return Err(crate::zerr!(
                        "write {} = 1 failed: {error}",
                        kill_path.display()
                    ))
                }
            }
        }

        self.freeze(true)?;
        let procs_path = self.path.join("cgroup.procs");
        let procs = fs::read_to_string(&procs_path)
            .map_err(|error| crate::zerr!("read {} failed: {error}", procs_path.display()))?;
        for value in procs.split_whitespace() {
            let pid = value.parse::<libc::pid_t>().map_err(|_| {
                crate::zerr!("parse PID {value:?} from {} failed", procs_path.display())
            })?;
            if let Err(error) = crate::syscalls::kill_if_exists(pid, libc::SIGKILL) {
                return Err(crate::zerr!(
                    "kill process {pid} in {} failed: {error}",
                    self.path.display()
                ));
            }
        }
        self.wait_populated(false, KILL_WAIT)
    }

    fn wait_populated(&self, want: bool, timeout: Duration) -> ZResult<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if read_populated(&self.path) == Some(want) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(crate::zerr!(
                    "timed out waiting for cgroup {} to become {}",
                    self.path.display(),
                    if want { "populated" } else { "empty" }
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Benchmark helper: read peak memory usage (used by the bench harness).
    #[allow(dead_code)]
    pub fn read_peak(&self) -> ZResult<String> {
        fs::read_to_string(self.path.join("memory.peak")).map_err(|e| e.into())
    }

    /// Clean up after the container exits: rmdir the leaf directory (control files
    /// are reclaimed by the kernel). The explicit method is kept for callers
    /// that document the end of the run; [`Drop`] also performs the cleanup so
    /// setup failures cannot leak a cgroup.
    pub fn cleanup(mut self) {
        // Cleanup is a process-tree boundary, not just directory removal. This
        // is essential for host PID namespaces and for exec workers that are
        // not descendants of the container's top-level process.
        if let Err(error) = self.kill_all() {
            eprintln!(
                "zerun: warning: terminate cgroup {} before cleanup: {error}",
                self.path.display()
            );
        }
        self.cleanup_on_drop = true;
    }
}

impl Drop for CgroupV2 {
    fn drop(&mut self) {
        if !self.cleanup_on_drop {
            return;
        }
        // A cgroup can only be removed after its tasks have exited. Cleanup is
        // intentionally best-effort here: lifecycle reconciliation can retry
        // stale cgroups, while Drop must not mask the original setup error.
        let _ = fs::remove_dir(&self.path);
        let _ = fs::remove_dir(self.path.parent().unwrap_or(Path::new("/sys/fs/cgroup")));
    }
}

fn read_frozen(path: &Path) -> Option<bool> {
    let events = fs::read_to_string(path.join("cgroup.events")).ok()?;
    events.lines().find_map(|line| {
        let (key, value) = line.split_once(' ')?;
        (key == "frozen").then(|| value.trim() == "1")
    })
}

fn read_populated(path: &Path) -> Option<bool> {
    let events = fs::read_to_string(path.join("cgroup.events")).ok()?;
    events.lines().find_map(|line| {
        let (key, value) = line.split_once(' ')?;
        (key == "populated").then(|| value.trim() != "0")
    })
}

/// Validate and translate all requested limits before performing cgroupfs
/// writes. This prevents malformed options from producing partial updates.
fn plan_limit_writes(
    limits: &ResourceLimits,
    current_memory: Option<u64>,
    current_io: Option<&str>,
) -> ZResult<Vec<(&'static str, String)>> {
    let mut writes = Vec::new();
    if let Some(mem) = &limits.memory {
        let bytes = parse_size(mem)?;
        let swap_limit = match limits.memory_swap {
            Some(swap) => swap_limit_for_total(bytes, swap)?,
            None => bytes.to_string(),
        };
        writes.push(("memory.max", bytes.to_string()));
        writes.push(("memory.swap.max", swap_limit));
    } else if let Some(swap) = limits.memory_swap {
        let swap_limit = if swap < 0 {
            "max".to_string()
        } else {
            let memory = current_memory.ok_or_else(|| {
                crate::zerr!("finite memory-swap requires a finite current memory.max")
            })?;
            swap_limit_for_total(memory, swap)?
        };
        writes.push(("memory.swap.max", swap_limit));
    }
    if let Some(high) = &limits.memory_reservation {
        writes.push(("memory.high", parse_size(high)?.to_string()));
    }
    if let Some(cpus) = limits.cpus {
        writes.push(("cpu.max", format!("{} 100000", cpu_quota(cpus)?)));
    }
    if let Some(shares) = limits.cpu_shares {
        writes.push(("cpu.weight", cpu_weight(shares)?.to_string()));
    }
    if let Some(cpuset) = &limits.cpuset_cpus {
        writes.push(("cpuset.cpus", parse_cpuset(cpuset)?));
    }
    if let Some(mems) = &limits.cpuset_mems {
        writes.push(("cpuset.mems", parse_cpuset(mems)?));
    }
    if let Some(pids) = limits.pids {
        if pids == -1 {
            writes.push(("pids.max", "max".to_string()));
        } else if pids > 0 {
            writes.push(("pids.max", pids.to_string()));
        } else {
            return Err(crate::zerr!("pids limit must be positive or -1"));
        }
    }
    if !limits.io.is_empty() {
        let current_io = current_io.ok_or_else(|| crate::zerr!("current io.max is unavailable"))?;
        let merged = merge_io_max(current_io, &limits.io)?;
        // cgroupfs io.max accepts one complete device record per write. Keep
        // each line separate even though the merged view is easier to build as
        // one string; a multi-line write is rejected with EINVAL.
        for line in merged.lines() {
            writes.push(("io.max", line.to_string()));
        }
    }
    if limits.oom_group {
        writes.push(("memory.oom.group", "1".to_string()));
    }
    Ok(writes)
}

fn merge_io_limits(by_device: &mut BTreeMap<String, IoLimit>, limits: &[IoLimit]) {
    for limit in limits {
        let entry = by_device
            .entry(limit.device.clone())
            .or_insert_with(|| IoLimit {
                device: limit.device.clone(),
                ..IoLimit::default()
            });
        entry.read_bps = limit.read_bps.or(entry.read_bps);
        entry.write_bps = limit.write_bps.or(entry.write_bps);
        entry.read_iops = limit.read_iops.or(entry.read_iops);
        entry.write_iops = limit.write_iops.or(entry.write_iops);
    }
}

/// Merge new device limits into the kernel's current `io.max` view.
///
/// A cgroup `io.max` write is line-oriented: each supplied device line replaces
/// the complete four-dimension record for that device. Without this merge,
/// updating one rate would silently reset unrelated devices or the other
/// directions to `max`.
fn merge_io_max(current: &str, updates: &[IoLimit]) -> ZResult<String> {
    let mut by_device = parse_io_max(current)?;
    merge_io_limits(&mut by_device, updates);
    Ok(render_io_limits(by_device))
}

fn parse_io_max(current: &str) -> ZResult<BTreeMap<String, IoLimit>> {
    let mut by_device = BTreeMap::new();
    for (line_index, line) in current.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let device = fields
            .next()
            .ok_or_else(|| crate::zerr!("malformed io.max line {}", line_index + 1))?;
        let device = parse_device(device)?;
        let mut limit = IoLimit {
            device: device.clone(),
            ..IoLimit::default()
        };
        let mut seen = [false; 4];
        for field in fields {
            let (key, value) = field.split_once('=').ok_or_else(|| {
                crate::zerr!(
                    "malformed io.max field '{field}' on line {}",
                    line_index + 1
                )
            })?;
            let (index, slot) = match key {
                "rbps" => (0, &mut limit.read_bps),
                "wbps" => (1, &mut limit.write_bps),
                "riops" => (2, &mut limit.read_iops),
                "wiops" => (3, &mut limit.write_iops),
                _ => {
                    return Err(crate::zerr!(
                        "unknown io.max field '{key}' on line {}",
                        line_index + 1
                    ))
                }
            };
            if seen[index] {
                return Err(crate::zerr!(
                    "duplicate io.max field '{key}' on line {}",
                    line_index + 1
                ));
            }
            seen[index] = true;
            *slot = parse_io_max_value(value, line_index + 1, key)?;
        }
        if by_device.insert(device.clone(), limit).is_some() {
            return Err(crate::zerr!(
                "duplicate io.max device '{device}' on line {}",
                line_index + 1
            ));
        }
    }
    Ok(by_device)
}

fn parse_io_max_value(value: &str, line: usize, key: &str) -> ZResult<Option<u64>> {
    if value == "max" {
        return Ok(None);
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| crate::zerr!("invalid io.max {key} value '{value}' on line {line}"))?;
    Ok(Some(parsed))
}

fn render_io_limits(by_device: BTreeMap<String, IoLimit>) -> String {
    by_device
        .into_iter()
        .map(|(device, limit)| {
            format!(
                "{device} rbps={} wbps={} riops={} wiops={}",
                value_or_max(limit.read_bps),
                value_or_max(limit.write_bps),
                value_or_max(limit.read_iops),
                value_or_max(limit.write_iops)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn value_or_max(value: Option<u64>) -> String {
    value.map_or_else(|| "max".to_string(), |v| v.to_string())
}

/// Resolve a device path or `MAJOR:MINOR` to cgroups v2 device syntax.
pub fn parse_device(spec: &str) -> ZResult<String> {
    let spec = spec.trim();
    if let Some((major, minor)) = spec.split_once(':') {
        let parsed = if !major.is_empty()
            && !minor.is_empty()
            && !major.contains('/')
            && !minor.contains('/')
        {
            major
                .parse::<u64>()
                .ok()
                .zip(minor.parse::<u64>().ok())
                .filter(|(major, minor)| {
                    *major <= u64::from(u32::MAX) && *minor <= u64::from(u32::MAX)
                })
        } else {
            None
        };
        if let Some((major, minor)) = parsed {
            return Ok(format!("{major}:{minor}"));
        }
        return Err(crate::zerr!(
            "invalid device '{spec}' (use /dev/PATH or MAJOR:MINOR)"
        ));
    }

    let meta = fs::metadata(spec).map_err(|e| crate::zerr!("stat I/O device '{spec}': {e}"))?;
    if !meta.file_type().is_block_device() {
        return Err(crate::zerr!("I/O device '{spec}' is not a block device"));
    }
    let dev = meta.rdev();
    let major = (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)) as u64;
    let minor = ((dev & 0xff) | ((dev >> 12) & !0xff00)) as u64;
    Ok(format!("{major}:{minor}"))
}

/// Parse one `--device-read-bps`-style value (`DEVICE:LIMIT`).
pub fn parse_io_limit(flag: &str, value: &str) -> ZResult<IoLimit> {
    // Device identifiers may themselves contain a colon (MAJOR:MINOR), so the
    // final separator always belongs to the limit.
    let (device, limit) = value
        .rsplit_once(':')
        .ok_or_else(|| crate::zerr!("{flag}: expected DEVICE:LIMIT, got '{value}'"))?;
    let device = parse_device(device)?;
    let mut out = IoLimit {
        device,
        ..IoLimit::default()
    };
    match flag {
        "device-read-bps" => out.read_bps = Some(parse_positive_byte_size(limit)?),
        "device-write-bps" => out.write_bps = Some(parse_positive_byte_size(limit)?),
        "device-read-iops" => out.read_iops = Some(parse_positive_number(limit, flag)?),
        "device-write-iops" => out.write_iops = Some(parse_positive_number(limit, flag)?),
        other => return Err(crate::zerr!("unknown I/O limit flag '{other}'")),
    }
    Ok(out)
}

fn parse_positive_number(value: &str, what: &str) -> ZResult<u64> {
    let n = value
        .trim()
        .parse::<u64>()
        .map_err(|_| crate::zerr!("cannot parse {what}: '{value}'"))?;
    if n == 0 {
        return Err(crate::zerr!("{what} must be greater than zero"));
    }
    Ok(n)
}

/// Parse a positive byte size. Supports decimal-ish human units used by Docker
/// (`10m`, `10mb`, `1G`) as well as raw byte counts.
fn parse_positive_byte_size(value: &str) -> ZResult<u64> {
    let value = value.trim();
    let without_b = value
        .strip_suffix(['b', 'B'])
        .filter(|v| !v.is_empty())
        .unwrap_or(value);
    let bytes =
        parse_size(without_b).map_err(|_| crate::zerr!("cannot parse byte size: '{value}'"))?;
    if bytes == 0 {
        return Err(crate::zerr!("byte size must be greater than zero"));
    }
    Ok(bytes)
}

/// Parse Docker's `--cpu-shares` value. Zero means the default relative
/// weight; non-zero values use the historical cgroup v1 range.
pub fn parse_cpu_shares(value: &str) -> ZResult<u64> {
    let shares = value
        .trim()
        .parse::<u64>()
        .map_err(|_| crate::zerr!("cannot parse cpu shares: '{value}'"))?;
    if shares != 0 && !(2..=262_144).contains(&shares) {
        return Err(crate::zerr!(
            "cpu shares must be 0 or between 2 and 262144, got {shares}"
        ));
    }
    Ok(shares)
}

/// Translate cgroup v1 shares to cgroup v2's 1..10000 weight range using the
/// same piecewise mapping as OCI/runc. An explicit zero resets the default.
fn cpu_weight(shares: u64) -> ZResult<u64> {
    if shares == 0 {
        return Ok(100);
    }
    if !(2..=262_144).contains(&shares) {
        return Err(crate::zerr!(
            "cpu shares must be between 2 and 262144, got {shares}"
        ));
    }
    Ok(if shares >= 1024 {
        1 + (shares - 2) * 9999 / 262_142
    } else {
        1 + (shares - 2) * 9998 / 1022
    })
}

/// Validate a cgroups v2 CPU/memory-node list (`cpuset.cpus` or `cpuset.mems`).
/// Kernel bounds are checked by cgroupfs; this catches malformed values early
/// and keeps whitespace/control characters out of service arguments.
pub fn parse_cpuset(value: &str) -> ZResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(crate::zerr!("cpuset list cannot be empty"));
    }
    let valid_group = |group: &str| {
        let (start, end) = match group.split_once('-') {
            Some((start, end)) => (start, end),
            None => (group, group),
        };
        let parsed = |s: &str| -> Option<u64> {
            if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            s.parse::<u64>().ok()
        };
        matches!(
            (parsed(start), parsed(end)),
            (Some(start), Some(end)) if start <= end
        )
    };
    if !value.split(',').all(valid_group) {
        return Err(crate::zerr!(
            "invalid cpuset list '{value}' (expected N, N-M, or comma-separated groups)"
        ));
    }
    Ok(value.to_string())
}

fn validate_container_id(id: &str) -> ZResult<()> {
    if !(1..=64).contains(&id.len()) || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(crate::zerr!("invalid container id '{id}' for cgroup"));
    }
    Ok(())
}

fn require_controller(parent: &Path, controller: &str) -> ZResult<()> {
    let available = fs::read_to_string(parent.join("cgroup.controllers"))
        .map_err(|e| crate::zerr!("read {}: {e}", parent.join("cgroup.controllers").display()))?;
    if !available.split_whitespace().any(|c| c == controller) {
        return Err(crate::zerr!(
            "cgroups v2 '{controller}' controller is unavailable on this host"
        ));
    }
    Ok(())
}

/// Locate the cgroup2 mount from /proc/self/mountinfo, falling back to
/// /sys/fs/cgroup.
pub fn detect_cgroup2_root() -> ZResult<PathBuf> {
    if let Ok(info) = fs::read_to_string("/proc/self/mountinfo") {
        for line in info.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // mountinfo: ... mountpoint ... - fstype source ...
            if let Some(pos) = fields.iter().position(|f| *f == "-") {
                if pos + 1 < fields.len() && fields[pos + 1] == "cgroup2" && pos >= 4 {
                    // Column 5 (index 4) is the mount point; spaces are \040-escaped.
                    return Ok(PathBuf::from(fields[4].replace("\\040", " ")));
                }
            }
        }
    }
    let fallback = PathBuf::from("/sys/fs/cgroup");
    if fallback.join("cgroup.controllers").exists() {
        return Ok(fallback);
    }
    Err(crate::zerr!(
        "no cgroup v2 unified hierarchy found (/sys/fs/cgroup/cgroup.controllers missing). \
         Boot with cgroup v2 (systemd.unified_cgroup_hierarchy=1) or add a v1 adapter layer"
    ))
}

/// Enable `want` controllers on `parent`'s subtree_control (idempotent).
/// Controllers the kernel does not expose are silently skipped so the function
/// works across hosts with different controller sets.
fn enable_controllers(parent: &Path, want: &[&str]) -> ZResult<()> {
    let available = fs::read_to_string(parent.join("cgroup.controllers"))
        .map_err(|e| crate::zerr!("read {}: {e}", parent.join("cgroup.controllers").display()))?;
    let enabled = fs::read_to_string(parent.join("cgroup.subtree_control")).unwrap_or_default();
    let mut to_enable: Vec<&str> = Vec::new();
    for c in want {
        if available.split_whitespace().any(|a| a == *c)
            && !enabled
                .split_whitespace()
                .any(|e| e.trim_start_matches('+') == *c)
        {
            to_enable.push(c);
        }
    }
    if to_enable.is_empty() {
        return Ok(());
    }
    let cmd = to_enable
        .iter()
        .map(|c| format!("+{c}"))
        .collect::<Vec<_>>()
        .join(" ");
    fs::write(parent.join("cgroup.subtree_control"), cmd.as_bytes()).map_err(|e| {
        crate::zerr!(
            "enable controllers [{cmd}] on {} failed: {e}. Hint: root or a delegated cgroup v2 subtree is required",
            parent.display()
        )
    })
}

/// Convert Docker's total memory+swap ceiling to cgroup v2's swap-only limit.
/// A negative total means unlimited swap; otherwise the total must include the
/// memory ceiling and only the remainder belongs in `memory.swap.max`.
fn swap_limit_for_total(memory: u64, total: i64) -> ZResult<String> {
    if total < 0 {
        return Ok("max".to_string());
    }
    let total = u64::try_from(total).map_err(|_| crate::zerr!("memory-swap is invalid"))?;
    if total < memory {
        return Err(crate::zerr!(
            "memory-swap {total} must be >= memory {memory}"
        ));
    }
    Ok((total - memory).to_string())
}

/// Parse Docker-style memory+swap ceilings. `-1`/`unlimited` means no swap
/// ceiling; otherwise values use the same size suffixes as memory.
pub fn parse_memory_swap(value: &str) -> ZResult<i64> {
    let value = value.trim();
    if value == "-1" || value.eq_ignore_ascii_case("unlimited") {
        return Ok(-1);
    }
    let bytes =
        parse_size(value).map_err(|_| crate::zerr!("cannot parse memory-swap size: '{value}'"))?;
    if bytes == 0 {
        return Err(crate::zerr!(
            "memory-swap must be greater than zero or unlimited"
        ));
    }
    i64::try_from(bytes).map_err(|_| crate::zerr!("memory-swap size is too large"))
}

/// Shared byte-size parser kept behind the cgroup module's existing helper so
/// callers and tests retain the resource-limit error boundary.
fn parse_size(s: &str) -> ZResult<u64> {
    crate::units::parse_size(s)
}

/// Parse and validate a fractional CPU count before a cgroup is created or
/// updated. The cgroup quota has 10,000 microsecond granularity, so values
/// that would round down to zero are rejected instead of failing later in the
/// kernel.
pub fn parse_cpus(value: &str) -> ZResult<f64> {
    let cpus = value
        .trim()
        .parse::<f64>()
        .map_err(|_| crate::zerr!("cannot parse cpus: '{value}'"))?;
    cpu_quota(cpus)?;
    Ok(cpus)
}

/// Convert a fractional CPU count into the cgroup v2 quota (100 ms period).
fn cpu_quota(cpus: f64) -> ZResult<i64> {
    if !cpus.is_finite() || cpus <= 0.0 {
        return Err(crate::zerr!(
            "cpus must be a finite value greater than zero"
        ));
    }
    let quota = (cpus * 100_000.0).round();
    if !quota.is_finite() || quota < 1.0 || quota > i64::MAX as f64 {
        return Err(crate::zerr!("cpus value is outside the supported range"));
    }
    Ok(quota as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_rejects_missing_cgroup_dir() {
        let missing =
            std::env::temp_dir().join(format!("zerun-cgroup-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&missing);
        assert!(CgroupV2::open(&missing).is_err());
    }

    #[test]
    fn converts_total_memory_swap_to_swap_only_limit() {
        assert_eq!(
            swap_limit_for_total(64 * 1024 * 1024, 128 * 1024 * 1024).unwrap(),
            "67108864"
        );
        assert_eq!(
            swap_limit_for_total(64 * 1024 * 1024, 64 * 1024 * 1024).unwrap(),
            "0"
        );
        assert_eq!(swap_limit_for_total(64 * 1024 * 1024, -1).unwrap(), "max");
        assert!(swap_limit_for_total(128, 127).is_err());
    }

    #[test]
    fn parses_memory_swap_ceilings() {
        assert_eq!(parse_memory_swap("64M").unwrap(), 64 * 1024 * 1024);
        assert_eq!(parse_memory_swap("-1").unwrap(), -1);
        assert_eq!(parse_memory_swap("unlimited").unwrap(), -1);
        assert!(parse_memory_swap("0").is_err());
        assert!(parse_memory_swap("bad").is_err());
    }

    #[test]
    fn parses_cpu_and_memory_node_lists() {
        assert_eq!(parse_cpuset("0").unwrap(), "0");
        assert_eq!(parse_cpuset("0-3,8").unwrap(), "0-3,8");
        assert_eq!(parse_cpuset(" 1,2-4 ").unwrap(), "1,2-4");
        assert!(parse_cpuset("").is_err());
        assert!(parse_cpuset("4-2").is_err());
        assert!(parse_cpuset("0,,2").is_err());
        assert!(parse_cpuset("0-").is_err());
        assert!(parse_cpuset("0;2").is_err());
    }

    #[test]
    fn parses_device_io_limits() {
        let limit = parse_io_limit("device-read-bps", "8:48:1m").unwrap();
        assert_eq!(limit.device, "8:48");
        assert_eq!(limit.read_bps, Some(1024 * 1024));
        assert_eq!(limit.write_bps, None);

        let limit = parse_io_limit("device-write-iops", "/dev/null:20");
        assert!(limit.is_err()); // /dev/null is a character device
        assert!(parse_io_limit("device-read-iops", "bad:10").is_err());
        assert!(parse_io_limit("device-write-iops", "8:48:0").is_err());
    }

    #[test]
    fn groups_device_limits_into_io_max() {
        let value = merge_io_max(
            "",
            &[
                IoLimit {
                    device: "8:48".into(),
                    read_bps: Some(1024),
                    ..IoLimit::default()
                },
                IoLimit {
                    device: "8:48".into(),
                    write_iops: Some(20),
                    ..IoLimit::default()
                },
                IoLimit {
                    device: "8:16".into(),
                    read_iops: Some(3),
                    ..IoLimit::default()
                },
            ],
        )
        .unwrap();
        assert_eq!(
            value,
            "8:16 rbps=max wbps=max riops=3 wiops=max\n\
             8:48 rbps=1024 wbps=max riops=max wiops=20"
        );
    }

    #[test]
    fn io_updates_preserve_unmentioned_devices_and_dimensions() {
        let current = "8:16 rbps=100 wbps=200 riops=max wiops=50\n                       8:32 rbps=10 wbps=max riops=20 wiops=max";
        let updates = [
            IoLimit {
                device: "8:16".into(),
                read_bps: Some(300),
                ..IoLimit::default()
            },
            IoLimit {
                device: "8:48".into(),
                write_iops: Some(7),
                ..IoLimit::default()
            },
        ];
        assert_eq!(
            merge_io_max(current, &updates).unwrap(),
            concat!(
                "8:16 rbps=300 wbps=200 riops=max wiops=50\n",
                "8:32 rbps=10 wbps=max riops=20 wiops=max\n",
                "8:48 rbps=max wbps=max riops=max wiops=7"
            )
        );
        assert!(merge_io_max("not-a-device rbps=1", &[]).is_err());
        assert!(merge_io_max("8:16 rbps=1 rbps=2", &[]).is_err());
        assert!(merge_io_max("8:16 rbps=1 unknown=2", &[]).is_err());
    }

    #[test]
    fn io_plan_uses_one_cgroup_write_per_device() {
        let limits = ResourceLimits {
            io: vec![IoLimit {
                device: "8:16".into(),
                write_bps: Some(2048),
                ..IoLimit::default()
            }],
            ..ResourceLimits::default()
        };
        let writes = plan_limit_writes(
            &limits,
            None,
            Some(concat!(
                "8:16 rbps=1024 wbps=max riops=max wiops=max\n",
                "8:32 rbps=max wbps=4096 riops=max wiops=max"
            )),
        )
        .unwrap();
        let io_writes: Vec<_> = writes
            .iter()
            .filter(|(file, _)| *file == "io.max")
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(
            io_writes,
            [
                "8:16 rbps=1024 wbps=2048 riops=max wiops=max",
                "8:32 rbps=max wbps=4096 riops=max wiops=max"
            ]
        );
    }

    #[test]
    fn parses_memory_sizes() {
        assert_eq!(parse_size("64M").unwrap(), 64 * 1024 * 1024);
        assert_eq!(parse_size("1G").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("512m").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_size("1k").unwrap(), 1024);
        assert_eq!(parse_size("4096").unwrap(), 4096);
        assert_eq!(parse_size("1.5M").unwrap(), 1_572_864);
        assert_eq!(parse_size(".5K").unwrap(), 512);
        assert_eq!(parse_size("1MB").unwrap(), 1024 * 1024);
        assert_eq!(parse_size("1GB").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("1B").unwrap(), 1);
        assert_eq!(parse_size("1T").unwrap(), 1024 * 1024 * 1024 * 1024);
        assert!(parse_size("abc").is_err());
        assert!(parse_size("NaN").is_err());
        assert!(parse_size("inf").is_err());
        assert!(parse_size("-1M").is_err());
        assert!(parse_size("1..5M").is_err());
        assert!(parse_size("18446744073709551616").is_err());
    }

    #[test]
    fn translates_cpu_shares_to_cgroup_v2_weight() {
        assert_eq!(parse_cpu_shares("0").unwrap(), 0);
        assert_eq!(parse_cpu_shares("2").unwrap(), 2);
        assert_eq!(parse_cpu_shares("1024").unwrap(), 1024);
        assert_eq!(parse_cpu_shares("262144").unwrap(), 262_144);
        assert!(parse_cpu_shares("1").is_err());
        assert!(parse_cpu_shares("262145").is_err());
        assert!(parse_cpu_shares("-1").is_err());
        assert_eq!(cpu_weight(0).unwrap(), 100);
        assert_eq!(cpu_weight(2).unwrap(), 1);
        assert_eq!(cpu_weight(1024).unwrap(), 39);
        assert_eq!(cpu_weight(2048).unwrap(), 79);
        assert_eq!(cpu_weight(262_144).unwrap(), 10_000);
    }

    #[test]
    fn cpu_share_plan_writes_cgroup_v2_weight() {
        let limits = ResourceLimits {
            cpu_shares: Some(2048),
            ..ResourceLimits::default()
        };
        assert_eq!(
            plan_limit_writes(&limits, None, None).unwrap(),
            vec![("cpu.weight", "79".to_string())]
        );
    }

    #[test]
    fn pids_limit_plan_supports_positive_and_unlimited_values() {
        let limited = ResourceLimits {
            pids: Some(128),
            ..ResourceLimits::default()
        };
        assert_eq!(
            plan_limit_writes(&limited, None, None).unwrap(),
            vec![("pids.max", "128".to_string())]
        );

        let unlimited = ResourceLimits {
            pids: Some(-1),
            ..ResourceLimits::default()
        };
        assert_eq!(
            plan_limit_writes(&unlimited, None, None).unwrap(),
            vec![("pids.max", "max".to_string())]
        );

        for invalid in [0, -2] {
            let limits = ResourceLimits {
                pids: Some(invalid),
                ..ResourceLimits::default()
            };
            assert!(plan_limit_writes(&limits, None, None).is_err());
        }
    }

    #[test]
    fn validates_cpu_quotas_without_float_overflow() {
        assert_eq!(parse_cpus(" 0.5 ").unwrap(), 0.5);
        assert!(parse_cpus("NaN").is_err());
        assert!(parse_cpus("0.000001").is_err());
        assert_eq!(cpu_quota(0.5).unwrap(), 50_000);
        assert_eq!(cpu_quota(1.25).unwrap(), 125_000);
        assert!(cpu_quota(0.000001).is_err());
        assert!(cpu_quota(0.0).is_err());
        assert!(cpu_quota(f64::NAN).is_err());
        assert!(cpu_quota(f64::INFINITY).is_err());
    }

    #[test]
    fn cgroup_container_paths_reject_untrusted_ids() {
        assert!(CgroupV2::container_path("../outside").is_err());
        assert!(CgroupV2::container_path("id/child").is_err());
        assert!(!CgroupV2::is_container_path(
            "../outside",
            Path::new("/sys/fs/cgroup/zerun/../outside")
        ));
    }

    #[test]
    fn remove_for_container_rejects_untrusted_paths() {
        let err = CgroupV2::remove_for_container("0123456789ab", Path::new("/tmp/elsewhere"))
            .unwrap_err();
        assert!(err.to_string().contains("refusing to remove cgroup"));
    }

    #[test]
    fn dropping_a_cgroup_removes_the_leaf_and_empty_parent() {
        let root = std::env::temp_dir().join(format!(
            "zerun-cgroup-drop-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let parent = root.join("zerun");
        let leaf = parent.join("container");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&leaf).unwrap();
        {
            let _cg = CgroupV2 {
                path: leaf.clone(),
                cleanup_on_drop: true,
            };
        }
        assert!(!leaf.exists());
        assert!(!parent.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn dropping_an_open_handle_does_not_remove_a_live_cgroup() {
        let root = std::env::temp_dir().join(format!(
            "zerun-cgroup-open-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let leaf = root.join("zerun/container");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&leaf).unwrap();
        {
            let _cg = CgroupV2::open(&leaf).unwrap();
        }
        assert!(leaf.is_dir());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn invalid_later_limit_does_not_partially_apply_earlier_values() {
        let root = std::env::temp_dir().join(format!(
            "zerun-cgroup-preflight-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let leaf = root.join("leaf");
        let parent = root.join("parent");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::create_dir_all(&parent).unwrap();
        std::fs::write(leaf.join("memory.max"), b"max").unwrap();

        let cgroup = CgroupV2::open(&leaf).unwrap();
        let limits = ResourceLimits {
            memory: Some("32M".to_string()),
            memory_reservation: Some("NaN".to_string()),
            ..ResourceLimits::default()
        };
        assert!(cgroup.apply_limits(&parent, &limits).is_err());
        assert_eq!(std::fs::read(leaf.join("memory.max")).unwrap(), b"max");
        assert!(!leaf.join("memory.swap.max").exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn io_update_merges_with_the_existing_io_max_file() {
        let root = std::env::temp_dir().join(format!(
            "zerun-cgroup-io-merge-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let leaf = root.join("leaf");
        let parent = root.join("parent");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::create_dir_all(&parent).unwrap();
        std::fs::write(parent.join("cgroup.controllers"), b"io").unwrap();
        let current = "8:16 rbps=100 wbps=200 riops=max wiops=50";
        std::fs::write(leaf.join("io.max"), current).unwrap();

        let cgroup = CgroupV2::open(&leaf).unwrap();
        let limits = ResourceLimits {
            io: vec![IoLimit {
                device: "8:16".into(),
                read_bps: Some(300),
                ..IoLimit::default()
            }],
            ..ResourceLimits::default()
        };
        cgroup.apply_limits(&parent, &limits).unwrap();
        assert_eq!(
            std::fs::read_to_string(leaf.join("io.max")).unwrap(),
            "8:16 rbps=300 wbps=200 riops=max wiops=50"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn missing_controller_does_not_partially_apply_other_limits() {
        let root = std::env::temp_dir().join(format!(
            "zerun-cgroup-controller-preflight-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let leaf = root.join("leaf");
        let parent = root.join("parent");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::create_dir_all(&parent).unwrap();
        std::fs::write(parent.join("cgroup.controllers"), b"memory cpu pids io").unwrap();
        std::fs::write(leaf.join("memory.max"), b"max").unwrap();

        let cgroup = CgroupV2::open(&leaf).unwrap();
        let limits = ResourceLimits {
            memory: Some("32M".to_string()),
            cpuset_cpus: Some("0".to_string()),
            ..ResourceLimits::default()
        };
        assert!(cgroup.apply_limits(&parent, &limits).is_err());
        assert_eq!(std::fs::read(leaf.join("memory.max")).unwrap(), b"max");
        assert!(!leaf.join("memory.swap.max").exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn writes_cgroup_freeze_state() {
        let dir = std::env::temp_dir().join(format!(
            "zerun-cgroup-freeze-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cg = CgroupV2 {
            path: dir.clone(),
            cleanup_on_drop: false,
        };
        cg.set_freeze(true).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("cgroup.freeze")).unwrap(),
            "1"
        );
        cg.set_freeze(false).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("cgroup.freeze")).unwrap(),
            "0"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kill_all_prefers_the_atomic_cgroup_kill_control_file() {
        let dir = std::env::temp_dir().join(format!(
            "zerun-cgroup-kill-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("cgroup.kill"), b"0").unwrap();
        std::fs::write(dir.join("cgroup.events"), b"populated 0\n").unwrap();
        let cg = CgroupV2::open(&dir).unwrap();

        cg.kill_all().unwrap();

        assert_eq!(std::fs::read(dir.join("cgroup.kill")).unwrap(), b"1");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kill_all_falls_back_when_cgroup_kill_is_unavailable() {
        let dir = std::env::temp_dir().join(format!(
            "zerun-cgroup-kill-fallback-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("cgroup.freeze"), b"0").unwrap();
        std::fs::write(
            dir.join("cgroup.events"),
            b"populated 0\nfrozen 1\nfrozen_effective 1\n",
        )
        .unwrap();
        std::fs::write(dir.join("cgroup.procs"), b"").unwrap();
        let cg = CgroupV2::open(&dir).unwrap();

        cg.kill_all().unwrap();

        assert_eq!(std::fs::read(dir.join("cgroup.freeze")).unwrap(), b"1");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kill_all_treats_a_missing_cgroup_as_already_clean() {
        let dir = std::env::temp_dir().join(format!(
            "zerun-cgroup-kill-missing-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let cg = CgroupV2::open(&dir);
        assert!(cg.is_err());

        // Construct the handle directly: open() intentionally rejects missing
        // lifecycle cgroups, but reconciliation can race their removal after
        // the persisted path has already been validated.
        let cg = CgroupV2 {
            path: dir,
            cleanup_on_drop: false,
        };
        cg.kill_all().unwrap();
    }
}
