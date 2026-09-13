//! Resource constraints: cgroups v2.
//!
//! Implements the direct cgroupfs driver (mkdir under the unified hierarchy).
//! Besides hard limits it applies `memory.high` (soft reservation) and
//! `memory.oom.group` for all-at-once OOM behavior. A systemd-scope driver and
//! a cgroups v1 fallback belong to later milestones.
use crate::error::{last_err, ZResult};
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
    /// Create the sub-hierarchy <cgroup2>/zerun/<id>.
    ///
    /// cgroups v2 requires every controller to be enabled in the parent's
    /// subtree_control before the leaf gets the corresponding control files, so
    /// the intermediate <cgroup2>/zerun level enables cpu/memory/pids on demand.
    pub fn create(id: &str, limits: &ResourceLimits) -> ZResult<Self> {
        if limits.memory.is_none() && limits.memory_swap.is_some_and(|swap| swap >= 0) {
            return Err(crate::zerr!(
                "a finite memory-swap ceiling requires --memory"
            ));
        }
        let root = detect_cgroup2_root()?;
        let parent = root.join("zerun");
        let path = parent.join(id);
        fs::create_dir_all(&path).map_err(|e| {
            crate::zerr!(
                "create cgroup {} failed: {e}. Hint: root or a delegated cgroup v2 subtree is required",
                path.display()
            )
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
    /// `zerun update`).
    pub fn apply_limits(&self, parent: &Path, limits: &ResourceLimits) -> ZResult<()> {
        if let Some(mem) = &limits.memory {
            let bytes = parse_size(mem)?;
            // Docker's --memory-swap is a total memory+swap ceiling, while
            // cgroup v2's memory.swap.max contains only the swap portion.
            // Validate before writing memory.max so an invalid pair cannot
            // leave a partially-applied resource configuration behind.
            let swap_limit = match limits.memory_swap {
                Some(swap) => swap_limit_for_total(bytes, swap)?,
                None => bytes.to_string(),
            };
            self.write("memory.max", bytes.to_string())?;
            self.write("memory.swap.max", swap_limit)?;
        } else if let Some(swap) = limits.memory_swap {
            if swap < 0 {
                self.write("memory.swap.max", "max".to_string())?;
            } else {
                // `update --memory-swap` changes the total ceiling while the
                // existing memory.max supplies the memory portion.
                let memory = fs::read_to_string(self.path.join("memory.max"))
                    .map_err(|e| crate::zerr!("read current memory.max failed: {e}"))?;
                let memory = memory.trim().parse::<u64>().map_err(|_| {
                    crate::zerr!("finite memory-swap requires a finite current memory.max")
                })?;
                self.write("memory.swap.max", swap_limit_for_total(memory, swap)?)?;
            }
        }
        if let Some(high) = &limits.memory_reservation {
            let bytes = parse_size(high)?;
            self.write("memory.high", bytes.to_string())?;
        }
        if let Some(cpus) = limits.cpus {
            let quota = cpu_quota(cpus)?;
            self.write("cpu.max", format!("{quota} 100000"))?;
        }
        if let Some(cpuset) = &limits.cpuset_cpus {
            require_controller(parent, "cpuset")?;
            self.write("cpuset.cpus", cpuset.clone())?;
        }
        if let Some(mems) = &limits.cpuset_mems {
            require_controller(parent, "cpuset")?;
            self.write("cpuset.mems", mems.clone())?;
        }
        if let Some(pids) = limits.pids {
            self.write("pids.max", pids.to_string())?;
        }
        if !limits.io.is_empty() {
            require_controller(parent, "io")?;
            self.write("io.max", io_max_value(&limits.io))?;
        }
        if limits.oom_group {
            self.write("memory.oom.group", "1".to_string())?;
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

    /// Write the cloned init PID into cgroup.procs right after clone.
    /// The child may already have exited (e.g. /bin/true): ESRCH/ENOENT is normal.
    pub fn attach(&self, pid: i32) -> ZResult<()> {
        match fs::write(self.path.join("cgroup.procs"), pid.to_string()) {
            Ok(_) => Ok(()),
            Err(e) => match e.raw_os_error() {
                Some(libc::ESRCH) | Some(libc::ENOENT) => Ok(()),
                _ => Err(last_err("write cgroup.procs")),
            },
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

/// Turn Docker-style device limits into one compact `io.max` value.
fn io_max_value(limits: &[IoLimit]) -> String {
    let mut by_device: BTreeMap<String, IoLimit> = BTreeMap::new();
    for limit in limits {
        let entry = by_device.entry(limit.device.clone()).or_default();
        entry.read_bps = limit.read_bps.or(entry.read_bps);
        entry.write_bps = limit.write_bps.or(entry.write_bps);
        entry.read_iops = limit.read_iops.or(entry.read_iops);
        entry.write_iops = limit.write_iops.or(entry.write_iops);
    }
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

/// Parse K/M/G size suffixes into bytes.
///
/// This deliberately avoids floating-point parsing. Resource limits are
/// security-sensitive, and `f64` accepts values such as `NaN` and `inf`; the
/// subsequent float-to-integer cast would otherwise silently turn them into
/// an unexpected limit. Decimal values are truncated to whole bytes, matching
/// the previous behavior for inputs such as `1.5M`.
fn parse_size(s: &str) -> ZResult<u64> {
    let s = s.trim();
    let (number, multiplier) = match s.as_bytes().last().copied() {
        Some(b'k' | b'K') => (&s[..s.len() - 1], 1024u64),
        Some(b'm' | b'M') => (&s[..s.len() - 1], 1024u64 * 1024),
        Some(b'g' | b'G') => (&s[..s.len() - 1], 1024u64 * 1024 * 1024),
        _ => (s, 1u64),
    };
    let number = number.trim();
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    if whole.is_empty() && fraction.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 38
    {
        return Err(crate::zerr!("cannot parse memory size: {s}"));
    }

    let whole = if whole.is_empty() {
        0u128
    } else {
        whole
            .parse::<u128>()
            .map_err(|_| crate::zerr!("memory size is too large: {s}"))?
    };
    let scaled_whole = whole
        .checked_mul(u128::from(multiplier))
        .ok_or_else(|| crate::zerr!("memory size is too large: {s}"))?;
    let fractional = if fraction.is_empty() {
        0u128
    } else {
        let digits = fraction
            .parse::<u128>()
            .map_err(|_| crate::zerr!("memory size is too large: {s}"))?;
        let denominator = 10u128.pow(fraction.len() as u32);
        digits
            .checked_mul(u128::from(multiplier))
            .ok_or_else(|| crate::zerr!("memory size is too large: {s}"))?
            / denominator
    };
    u64::try_from(
        scaled_whole
            .checked_add(fractional)
            .ok_or_else(|| crate::zerr!("memory size is too large: {s}"))?,
    )
    .map_err(|_| crate::zerr!("memory size is too large: {s}"))
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
        let value = io_max_value(&[
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
        ]);
        assert_eq!(
            value,
            "8:16 rbps=max wbps=max riops=3 wiops=max\n\
             8:48 rbps=1024 wbps=max riops=max wiops=20"
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
        assert!(parse_size("abc").is_err());
        assert!(parse_size("NaN").is_err());
        assert!(parse_size("inf").is_err());
        assert!(parse_size("-1M").is_err());
        assert!(parse_size("1..5M").is_err());
        assert!(parse_size("18446744073709551616").is_err());
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
}
