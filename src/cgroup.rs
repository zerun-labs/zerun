//! Resource constraints: cgroups v2.
//!
//! Implements the direct cgroupfs driver (mkdir under the unified hierarchy).
//! A systemd-scope driver and a cgroups v1 fallback belong to later milestones.
use crate::error::{last_err, ZResult};
use crate::trace;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Clone)]
pub struct ResourceLimits {
    /// Raw size strings such as "64M", "512m", "1G"; None means no limit.
    pub memory: Option<String>,
    /// CPU cores (fractional), e.g. 0.5 -> cpu.max "50000 100000".
    pub cpus: Option<f64>,
    /// Process count limit pids.max (default suggestion for low-end hosts: 256).
    pub pids: Option<i64>,
}

pub struct CgroupV2 {
    path: PathBuf,
}

impl CgroupV2 {
    /// Create the sub-hierarchy <cgroup2>/zerun/<id>.
    pub fn create(id: &str, limits: &ResourceLimits) -> ZResult<Self> {
        let root = detect_cgroup2_root()?;
        let path = root.join("zerun").join(id);
        fs::create_dir_all(&path).map_err(|e| {
            crate::zerr!(
                "create cgroup {} failed: {e}. Hint: root or a delegated cgroup v2 subtree is required",
                path.display()
            )
        })?;
        let cg = CgroupV2 { path };

        if let Some(mem) = &limits.memory {
            let bytes = parse_size(mem)?;
            cg.write("memory.max", bytes.to_string())?;
            // Lock swap to the same ceiling so memory limits cannot be bypassed.
            let _ = cg.write("memory.swap.max", bytes.to_string());
        }
        if let Some(cpus) = limits.cpus {
            if cpus > 0.0 {
                let quota = (cpus * 100_000.0).round() as i64;
                cg.write("cpu.max", format!("{quota} 100000"))?;
            }
        }
        if let Some(pids) = limits.pids {
            cg.write("pids.max", pids.to_string())?;
        }
        trace::mark("parent:cgroup:configured");
        Ok(cg)
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

    /// Benchmark helper: read peak memory usage (used by the bench harness).
    #[allow(dead_code)]
    pub fn read_peak(&self) -> ZResult<String> {
        fs::read_to_string(self.path.join("memory.peak")).map_err(|e| e.into())
    }

    /// Clean up after the container exits: rmdir the leaf directory (control files
    /// are reclaimed by the kernel).
    pub fn cleanup(self) {
        let _ = fs::remove_dir(&self.path);
        let _ = fs::remove_dir(self.path.parent().unwrap_or(Path::new("/sys/fs/cgroup")));
    }
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

/// Parse K/M/G size suffixes into bytes.
fn parse_size(s: &str) -> ZResult<u64> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some(c) if c == 'k' || c == 'K' => (&s[..s.len() - 1], 1024u64),
        Some(c) if c == 'm' || c == 'M' => (&s[..s.len() - 1], 1024u64 * 1024),
        Some(c) if c == 'g' || c == 'G' => (&s[..s.len() - 1], 1024u64 * 1024 * 1024),
        _ => (s, 1u64),
    };
    num.trim()
        .parse::<f64>()
        .map(|n| (n * mult as f64) as u64)
        .map_err(|_| crate::zerr!("cannot parse memory size: {s}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_memory_sizes() {
        assert_eq!(parse_size("64M").unwrap(), 64 * 1024 * 1024);
        assert_eq!(parse_size("1G").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("512m").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_size("1k").unwrap(), 1024);
        assert_eq!(parse_size("4096").unwrap(), 4096);
        assert!(parse_size("abc").is_err());
    }
}
