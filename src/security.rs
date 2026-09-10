//! Security hardening (the area that v1 of the design doc missed entirely).
//!
//! Current stage: PR_SET_NO_NEW_PRIVS + a capability allowlist + a default
//! seccomp allowlist profile (M2). The allowlist mirrors Docker's default set
//! minus CAP_NET_RAW and CAP_SYS_ADMIN (design doc §4.6): containers can bind
//! low ports and manage their own files, but cannot sniff traffic or escape.
use crate::error::ZResult;
use crate::seccomp::{self, SeccompMode};
use crate::syscalls;
use crate::trace;
use std::collections::BTreeSet;

/// Linux capability numbers (stable ABI; the libc crate does not expose them).
pub(crate) mod cap {
    pub const CHOWN: i32 = 0;
    pub const DAC_OVERRIDE: i32 = 1;
    pub const FOWNER: i32 = 3;
    pub const FSETID: i32 = 4;
    pub const KILL: i32 = 5;
    pub const SETGID: i32 = 6;
    pub const SETUID: i32 = 7;
    pub const SETPCAP: i32 = 8;
    pub const NET_BIND_SERVICE: i32 = 10;
    pub const SYS_CHROOT: i32 = 18;
    pub const MKNOD: i32 = 27;
    pub const AUDIT_WRITE: i32 = 29;
    pub const SETFCAP: i32 = 31;
}

/// Capability names in kernel ABI order. Keep this table in sync with new
/// `CAP_*` constants added to Linux; unknown numeric state remains accepted.
const CAPABILITY_NAMES: &[&str] = &[
    "CHOWN",
    "DAC_OVERRIDE",
    "DAC_READ_SEARCH",
    "FOWNER",
    "FSETID",
    "KILL",
    "SETGID",
    "SETUID",
    "SETPCAP",
    "LINUX_IMMUTABLE",
    "NET_BIND_SERVICE",
    "NET_BROADCAST",
    "NET_ADMIN",
    "NET_RAW",
    "IPC_LOCK",
    "IPC_OWNER",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_CHROOT",
    "SYS_PTRACE",
    "SYS_PACCT",
    "SYS_ADMIN",
    "SYS_BOOT",
    "SYS_NICE",
    "SYS_RESOURCE",
    "SYS_TIME",
    "SYS_TTY_CONFIG",
    "MKNOD",
    "LEASE",
    "AUDIT_WRITE",
    "AUDIT_CONTROL",
    "SETFCAP",
    "MAC_OVERRIDE",
    "MAC_ADMIN",
    "SYSLOG",
    "WAKE_ALARM",
    "BLOCK_SUSPEND",
    "AUDIT_READ",
    "PERFMON",
    "BPF",
    "CHECKPOINT_RESTORE",
];

/// Capabilities kept by default (Docker-compatible, minus NET_RAW/SYS_ADMIN
/// per the design doc): containers can bind low ports and manage their own
/// files, but cannot sniff traffic or escape.
const DEFAULT_CAPS: &[i32] = &[
    cap::CHOWN,
    cap::DAC_OVERRIDE,
    cap::FSETID,
    cap::FOWNER,
    cap::MKNOD,
    cap::SETGID,
    cap::SETUID,
    cap::SETFCAP,
    cap::SETPCAP,
    cap::NET_BIND_SERVICE,
    cap::SYS_CHROOT,
    cap::KILL,
    cap::AUDIT_WRITE,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitySet {
    caps: BTreeSet<i32>,
}

impl Default for CapabilitySet {
    fn default() -> Self {
        Self::default_set()
    }
}

impl CapabilitySet {
    /// Docker-compatible secure baseline.
    pub fn default_set() -> Self {
        Self {
            caps: DEFAULT_CAPS.iter().copied().collect(),
        }
    }

    /// Resolve `--cap-add` and `--cap-drop` values against the default set.
    ///
    /// Drops are applied first and adds second, matching Docker's useful
    /// `--cap-drop ALL --cap-add NET_RAW` idiom. `ALL` expands to every
    /// capability supported by the running kernel (the v3 ABI caps at 63).
    pub fn resolve<'a>(
        adds: impl IntoIterator<Item = &'a String>,
        drops: impl IntoIterator<Item = &'a String>,
    ) -> ZResult<Self> {
        let adds = parse_requests_many(adds).map_err(|e| crate::zerr!("--cap-add: {e}"))?;
        let drops = parse_requests_many(drops).map_err(|e| crate::zerr!("--cap-drop: {e}"))?;
        let last = syscalls::cap_last_cap().min(63) as i32;

        let mut caps: BTreeSet<i32> = DEFAULT_CAPS.iter().copied().collect();
        for request in drops {
            match request {
                CapabilityRequest::All => caps.clear(),
                CapabilityRequest::Named(cap) => {
                    ensure_supported(cap, last)?;
                    caps.remove(&cap);
                }
            }
        }
        for request in adds {
            match request {
                CapabilityRequest::All => caps.extend(0..=last),
                CapabilityRequest::Named(cap) => {
                    ensure_supported(cap, last)?;
                    caps.insert(cap);
                }
            }
        }
        Ok(Self { caps })
    }

    /// Rebuild an exact set recorded in detached state.
    pub fn from_names(names: &[String]) -> ZResult<Self> {
        let last = syscalls::cap_last_cap().min(63) as i32;
        let mut caps = BTreeSet::new();
        for request in
            parse_requests_many(names).map_err(|e| crate::zerr!("invalid capabilities: {e}"))?
        {
            match request {
                CapabilityRequest::All => {
                    return Err(crate::zerr!(
                        "invalid capabilities: ALL is not valid in an exact capability set"
                    ))
                }
                CapabilityRequest::Named(cap) => {
                    ensure_supported(cap, last)?;
                    caps.insert(cap);
                }
            }
        }
        Ok(Self { caps })
    }

    /// Canonical names suitable for state.json and reconstructed launch args.
    pub fn names(&self) -> Vec<String> {
        self.caps.iter().copied().map(capability_name).collect()
    }

    pub fn contains(&self, cap: i32) -> bool {
        self.caps.contains(&cap)
    }

    fn iter(&self) -> impl Iterator<Item = i32> + '_ {
        self.caps.iter().copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CapabilityRequest {
    All,
    Named(i32),
}

/// Validate and normalize a comma-separated `--cap-add` / `--cap-drop` value.
pub fn parse_capability_list(raw: &str) -> Result<Vec<String>, String> {
    let requests = parse_requests(raw)?;
    Ok(requests
        .into_iter()
        .map(|request| match request {
            CapabilityRequest::All => "ALL".to_string(),
            CapabilityRequest::Named(cap) => capability_name(cap),
        })
        .collect())
}

fn parse_requests_many<'a>(
    values: impl IntoIterator<Item = &'a String>,
) -> Result<Vec<CapabilityRequest>, String> {
    let mut requests = BTreeSet::new();
    for value in values {
        requests.extend(parse_requests(value)?);
    }
    Ok(requests.into_iter().collect())
}

fn parse_requests(raw: &str) -> Result<Vec<CapabilityRequest>, String> {
    let values: Vec<&str> = raw.split(',').collect();
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(format!("invalid capability list '{raw}'"));
    }
    let requests = values
        .into_iter()
        .map(parse_request)
        .collect::<Result<BTreeSet<_>, _>>()?;
    Ok(requests.into_iter().collect())
}

fn parse_request(raw: &str) -> Result<CapabilityRequest, String> {
    let value = raw.trim().to_ascii_uppercase();
    if value == "ALL" {
        return Ok(CapabilityRequest::All);
    }
    let name = value.strip_prefix("CAP_").unwrap_or(&value);
    if name.is_empty() {
        return Err(format!("invalid capability '{raw}'"));
    }
    if let Ok(cap) = name.parse::<i32>() {
        if (0..=63).contains(&cap) {
            return Ok(CapabilityRequest::Named(cap));
        }
        return Err(format!("capability number '{raw}' is outside 0-63"));
    }
    CAPABILITY_NAMES
        .iter()
        .position(|candidate| *candidate == name)
        .map(|cap| CapabilityRequest::Named(cap as i32))
        .ok_or_else(|| format!("unknown capability '{raw}'"))
}

fn capability_name(cap: i32) -> String {
    CAPABILITY_NAMES
        .get(cap as usize)
        .map(|name| format!("CAP_{name}"))
        .unwrap_or_else(|| format!("CAP_{cap}"))
}

fn ensure_supported(cap: i32, last: i32) -> ZResult<()> {
    if cap > last {
        return Err(crate::zerr!(
            "capability {} is not supported by this kernel (cap_last_cap={last})",
            capability_name(cap)
        ));
    }
    Ok(())
}

/// Security sequence before the workload execs. Order matters: NO_NEW_PRIVS first,
/// then capabilities, then seccomp (loading a seccomp filter without CAP_SYS_ADMIN
/// requires NO_NEW_PRIVS to be set first).
pub fn harden(seccomp_mode: SeccompMode, capabilities: &CapabilitySet) -> ZResult<()> {
    trace::mark("child:security:begin");
    no_new_privs()?;
    trace::mark("child:nnp:done");
    apply_capabilities(capabilities)?;
    trace::mark("child:caps:done");
    seccomp::apply(seccomp_mode)?;
    trace::mark("child:security:done");
    Ok(())
}

/// Drop to a container user before exec (`--user`, or the image `config.User`).
///
/// Must run *after* `harden()`: the security sequence starts with CAP_SETUID /
/// CAP_SETGID still effective, and the capability drop needs root. Only the
/// numeric form works without `/etc/passwd`; named users resolve against the
/// *container's* passwd/group files after pivot_root. Rootless containers map
/// only uid/gid 0 to the host user, so any other requested identity is a clear
/// setup error.
pub fn switch_user(spec: Option<&str>, rootless: bool) -> ZResult<()> {
    let Some(raw) = spec else { return Ok(()) };
    let resolved = resolve_user_spec(raw)?;
    if rootless && (resolved.uid != 0 || resolved.gid != 0) {
        return Err(crate::zerr!(
            "rootless containers map only uid/gid 0; cannot switch to '{raw}'              (use --user 0 or run rootful)"
        ));
    }
    if resolved.uid == 0 && resolved.gid == 0 {
        return Ok(());
    }
    // Clear supplementary groups, then set gid before uid (the classic order:
    // after setgid, the effective uid is still root, so setuid is still allowed).
    let rc = unsafe { libc::setgroups(0, std::ptr::null()) };
    if rc != 0 {
        return Err(crate::zerr!(
            "setgroups failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if unsafe { libc::setgid(resolved.gid) } != 0 {
        return Err(crate::zerr!(
            "setgid({}) failed: {}",
            resolved.gid,
            std::io::Error::last_os_error()
        ));
    }
    if unsafe { libc::setuid(resolved.uid) } != 0 {
        return Err(crate::zerr!(
            "setuid({}) failed: {}",
            resolved.uid,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResolvedUser {
    uid: u32,
    gid: u32,
}

/// Parse Docker/OCI `user[:group]`. Both parts may be numeric or a name from
/// the container's `/etc/passwd` / `/etc/group`. A bare numeric user defaults
/// its gid to the same number (Docker convention); a bare named user uses its
/// passwd primary gid.
fn resolve_user_spec(raw: &str) -> ZResult<ResolvedUser> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(crate::zerr!("--user cannot be empty"));
    }
    let (user_part, group_part) = match raw.split_once(':') {
        Some((user, group)) => {
            if group.contains(':') {
                return Err(crate::zerr!(
                    "invalid --user '{raw}' (expected USER[:GROUP])"
                ));
            }
            (user, Some(group))
        }
        None => (raw, None),
    };
    if user_part.is_empty() {
        return Err(crate::zerr!("invalid --user '{raw}' (empty user)"));
    }

    let uid = match parse_id(user_part) {
        Some(id) => id,
        None => lookup_user_uid_gid(user_part)
            .map(|(uid, _)| uid)
            .ok_or_else(|| crate::zerr!("unknown user '{user_part}' in container /etc/passwd"))?,
    };
    let gid = match group_part {
        Some(group) => {
            if group.is_empty() {
                return Err(crate::zerr!("invalid --user '{raw}' (empty group)"));
            }
            match parse_id(group) {
                Some(id) => id,
                None => lookup_group_gid(group).ok_or_else(|| {
                    crate::zerr!("unknown group '{group}' in container /etc/group")
                })?,
            }
        }
        None => match parse_id(user_part) {
            Some(id) => id,
            None => lookup_user_uid_gid(user_part)
                .map(|(_, gid)| gid)
                .ok_or_else(|| {
                    crate::zerr!("unknown user '{user_part}' in container /etc/passwd")
                })?,
        },
    };
    Ok(ResolvedUser { uid, gid })
}

fn parse_id(value: &str) -> Option<u32> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn lookup_user_uid_gid(name: &str) -> Option<(u32, u32)> {
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 4 && fields[0] == name {
            return Some((fields[2].parse().ok()?, fields[3].parse().ok()?));
        }
    }
    None
}

fn lookup_group_gid(name: &str) -> Option<u32> {
    let text = std::fs::read_to_string("/etc/group").ok()?;
    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 3 && fields[0] == name {
            return fields[2].parse().ok();
        }
    }
    None
}

/// PR_SET_NO_NEW_PRIVS=1: setuid/setgid bits and file capabilities no longer
/// grant privileges after execve.
fn no_new_privs() -> ZResult<()> {
    syscalls::prctl_set(libc::PR_SET_NO_NEW_PRIVS, 1)
}

/// Drop every capability not in `keep` from the bounding set, then set the
/// process' effective/permitted/inheritable sets to exactly `keep` so the
/// workload starts with the allowlisted caps (Docker semantics).
fn apply_capabilities(keep: &CapabilitySet) -> ZResult<()> {
    let (lo, hi) = keep_mask(keep);
    let last = syscalls::cap_last_cap();
    for cap in 0..=last as i32 {
        if !keep.contains(cap) {
            syscalls::prctl_drop_cap(cap)?;
        }
    }
    // glibc has no capset wrapper; use the raw syscall with the kernel ABI structs.
    #[repr(C)]
    struct CapUserHeader {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapUserData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    // _LINUX_CAPABILITY_VERSION_3
    let header = CapUserHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [
        CapUserData {
            effective: lo,
            permitted: lo,
            inheritable: lo,
        },
        CapUserData {
            effective: hi,
            permitted: hi,
            inheritable: hi,
        },
    ];
    let rc = unsafe { libc::syscall(libc::SYS_capset, &header, data.as_mut_ptr()) };
    if rc != 0 {
        return Err(crate::zerr!(
            "capset failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Split a capability list into the two 32-bit words of the v3 ABI.
fn keep_mask(keep: &CapabilitySet) -> (u32, u32) {
    let mut lo = 0u32;
    let mut hi = 0u32;
    for c in keep.iter() {
        let c = c as u32;
        if c < 32 {
            lo |= 1u32 << c;
        } else {
            hi |= 1u32 << (c - 32);
        }
    }
    (lo, hi)
}

#[cfg(test)]
mod user_tests {
    use super::*;

    #[test]
    fn numeric_users_default_gid_to_uid() {
        assert_eq!(
            resolve_user_spec("1000").unwrap(),
            ResolvedUser {
                uid: 1000,
                gid: 1000
            }
        );
        assert_eq!(
            resolve_user_spec("1000:1001").unwrap(),
            ResolvedUser {
                uid: 1000,
                gid: 1001
            }
        );
        assert_eq!(
            resolve_user_spec("0:0").unwrap(),
            ResolvedUser { uid: 0, gid: 0 }
        );
    }

    #[test]
    fn malformed_users_are_rejected_without_touching_the_fs() {
        assert!(resolve_user_spec("").is_err());
        assert!(resolve_user_spec(":").is_err());
        assert!(resolve_user_spec("1000:").is_err());
        assert!(resolve_user_spec("1000:1000:extra").is_err());
        assert!(resolve_user_spec("-1").is_err());
    }
}

#[cfg(test)]
mod capability_tests {
    use super::*;
    use std::collections::BTreeSet;

    fn names(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    fn cap_id(name: &str) -> i32 {
        match parse_request(name).unwrap() {
            CapabilityRequest::Named(cap) => cap,
            CapabilityRequest::All => panic!("expected named capability"),
        }
    }

    #[test]
    fn default_set_matches_the_secure_baseline() {
        let caps = CapabilitySet::default();
        assert!(caps.contains(cap_id("CHOWN")));
        assert!(caps.contains(cap_id("NET_BIND_SERVICE")));
        assert!(caps.contains(cap_id("SETUID")));
        assert!(!caps.contains(cap_id("NET_RAW")));
        assert!(!caps.contains(cap_id("SYS_ADMIN")));
    }

    #[test]
    fn drop_all_then_add_keeps_only_the_requested_capability() {
        let caps = CapabilitySet::resolve(&names(&["NET_RAW"]), &names(&["ALL"])).unwrap();
        assert_eq!(caps.names(), vec!["CAP_NET_RAW"]);
    }

    #[test]
    fn adds_are_deduplicated_and_normalized() {
        let parsed = parse_capability_list("cap_net_raw, SYS_ADMIN,net-raw").unwrap_err();
        assert!(parsed.contains("unknown capability"));

        let parsed = parse_capability_list("cap_net_raw, SYS_ADMIN,NET_RAW").unwrap();
        assert_eq!(parsed, vec!["CAP_NET_RAW", "CAP_SYS_ADMIN"]);

        let parsed: BTreeSet<String> = parsed.into_iter().collect();
        let caps = CapabilitySet::resolve(&parsed, &BTreeSet::new()).unwrap();
        assert!(caps.contains(cap_id("NET_RAW")));
        assert!(caps.contains(cap_id("SYS_ADMIN")));
    }

    #[test]
    fn all_expands_to_the_running_kernel_maximum() {
        let caps = CapabilitySet::resolve(&names(&["ALL"]), &BTreeSet::new()).unwrap();
        let last = syscalls::cap_last_cap().min(63) as i32;
        assert!(caps.contains(0));
        assert!(caps.contains(last));
        assert_eq!(caps.names().len(), (last + 1) as usize);
    }

    #[test]
    fn exact_state_sets_round_trip_and_reject_all() {
        let caps = CapabilitySet::from_names(&["CAP_NET_RAW".to_string()]).unwrap();
        assert_eq!(caps.names(), vec!["CAP_NET_RAW"]);
        assert!(CapabilitySet::from_names(&["ALL".to_string()]).is_err());
        assert!(CapabilitySet::from_names(&["CAP_NOT_REAL".to_string()]).is_err());
        assert!(parse_capability_list("").is_err());
        assert!(parse_capability_list("NET_RAW,").is_err());
    }
}
