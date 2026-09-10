//! Read-only /proc inspection of running containers.
//!
//! `zerun top` needs the process list of a container's PID namespace without
//! entering it (daemonless: no setns, no helper process). The kernel exposes
//! every namespace member in the host `/proc` mount, so membership is decided
//! by comparing `/proc/<pid>/ns/pid` link targets with the container init's.

use std::fs;
use std::io;

/// One process inside a container's PID namespace (host-side view).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// Real UID from `/proc/<pid>/status`.
    pub uid: u32,
    pub pid: i32,
    pub ppid: i32,
    /// Controlling terminal as `ps` renders it (`?` when none).
    pub tty: String,
    /// Cumulative CPU time (utime + stime) rendered like `ps` TIME.
    pub cpu_time: String,
    /// Command line (`[comm]` when there is none, e.g. zombies).
    pub cmd: String,
}

/// List all processes in the PID namespace of `init_pid`, sorted by PID.
pub fn list_pid_namespace(init_pid: i32) -> io::Result<Vec<ProcessInfo>> {
    let want = ns_id(init_pid)?;
    let mut out = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        // Racy candidates (a process exits between readdir and its ns/pid
        // read) are simply skipped, matching `ps` semantics.
        match ns_id(pid) {
            Ok(id) if id == want => {}
            _ => continue,
        }
        if let Some(info) = read_process(pid) {
            out.push(info);
        }
    }
    out.sort_by_key(|p| p.pid);
    Ok(out)
}

/// Namespace inode id from a `/proc/<pid>/ns/pid` link (`pid:[4026532230]`).
fn ns_id(pid: i32) -> io::Result<String> {
    let text = fs::read_link(format!("/proc/{pid}/ns/pid"))?
        .to_string_lossy()
        .into_owned();
    let start = text.find('[').ok_or_else(|| bad_link(&text))? + 1;
    let end = text.find(']').ok_or_else(|| bad_link(&text))?;
    if start >= end {
        return Err(bad_link(&text));
    }
    Ok(text[start..end].to_string())
}

fn bad_link(text: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("malformed ns link {text}"),
    )
}

/// Snapshot one process from /proc; `None` when it vanished mid-read.
fn read_process(pid: i32) -> Option<ProcessInfo> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields = stat_fields(&stat)?;
    // Offsets are relative to the fields *after* `(comm)`: state, ppid, ...
    // so stat(5) field N lives at N - 3 (pid and comm were dropped).
    let ppid = fields.get(1)?.parse().ok()?;
    let tty_nr: u32 = fields.get(4)?.parse().ok()?;
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let comm = stat.get(open + 1..close)?.to_string();
    let uid = read_uid(pid)?;
    let cmd = fs::read_to_string(format!("/proc/{pid}/cmdline"))
        .ok()
        .map(|c| c.trim_end_matches('\0').replace('\0', " "))
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| format!("[{comm}]"));
    Some(ProcessInfo {
        uid,
        pid,
        ppid,
        tty: tty_name(tty_nr),
        cpu_time: format_cpu_time(utime.saturating_add(stime)),
        cmd,
    })
}

/// Split `/proc/<pid>/stat` into the whitespace-separated numeric fields
/// after `(comm)`. `comm` may itself contain spaces and parentheses, so the
/// split starts after the *last* `)`.
fn stat_fields(stat: &str) -> Option<Vec<&str>> {
    let close = stat.rfind(')')?;
    Some(stat.get(close + 1..)?.split_whitespace().collect())
}

/// Real UID (first `Uid:` field) from `/proc/<pid>/status`.
fn read_uid(pid: i32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// Render a `stat` `tty_nr` device the way `ps` does (`?` when none).
fn tty_name(tty_nr: u32) -> String {
    let major = (tty_nr >> 8) & 0xfff;
    let minor = (tty_nr & 0xff) | ((tty_nr >> 12) & 0xfff00);
    match major {
        4 => format!("tty{minor}"),
        136 => format!("pts/{minor}"),
        _ => "?".to_string(),
    }
}

fn clock_ticks_per_sec() -> u64 {
    // libc::sysconf is a plain libc query, not a raw syscall, so it stays
    // outside the syscalls.rs concentration rule.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if hz > 0 {
        hz as u64
    } else {
        100
    }
}

/// Render cumulative CPU ticks like `ps` TIME: `MM:SS`, hours prefixed.
fn format_cpu_time(ticks: u64) -> String {
    format_cpu_seconds(ticks / clock_ticks_per_sec())
}

/// Render whole CPU seconds like `ps` TIME (`MM:SS`, hours prefixed).
fn format_cpu_seconds(secs: u64) -> String {
    let (h, rem) = (secs / 3600, secs % 3600);
    if h > 0 {
        format!("{h}:{:02}:{:02}", rem / 60, rem % 60)
    } else {
        format!("{}:{:02}", rem / 60, rem % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_fields_skip_com_with_specials() {
        // comm contains a space, a paren, and the trailing fields must map
        // to stat(5) indexes shifted by 3.
        let stat = "1454 (my pro(g) v2) S 1300 1454 1300 34816 1454 \
                    4194304 1 0 0 0 7 3 0 0 20 0 1 0 30 900 1 \
                    18446744073709551615 1 1 0 0 0 0 0";
        let fields = stat_fields(stat).unwrap();
        assert_eq!(fields[0], "S");
        assert_eq!(fields[1], "1300"); // ppid
        assert_eq!(fields[4], "34816"); // tty_nr
        assert_eq!(fields[11], "7"); // utime
        assert_eq!(fields[12], "3"); // stime
        assert!(stat_fields("no parens here").is_none());
    }

    #[test]
    fn tty_names_match_ps_rendering() {
        assert_eq!(tty_name(0), "?");
        assert_eq!(tty_name((4 << 8) | 1), "tty1");
        assert_eq!(tty_name((136 << 8) | 7), "pts/7");
    }

    #[test]
    fn cpu_time_formats_like_ps() {
        assert_eq!(format_cpu_seconds(0), "0:00");
        assert_eq!(format_cpu_seconds(65 + 60 * 2), "3:05");
        assert_eq!(format_cpu_seconds(3661), "1:01:01");
    }
}
