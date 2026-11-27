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
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

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
/// then the resolved supplementary groups, capabilities, and seccomp. Replacing
/// groups before the capability drop keeps `--cap-drop SETGID` usable for containers
/// that remain uid/gid 0, while still preventing host group memberships from granting
/// access through group-owned bind mounts. Rootless user namespaces have
/// `setgroups=deny` and only map gid 0, so they cannot and need not perform it.
pub fn harden(
    seccomp_mode: SeccompMode,
    capabilities: &CapabilitySet,
    rootless: bool,
    supplementary_groups: &[u32],
) -> ZResult<()> {
    trace::mark("child:security:begin");
    no_new_privs()?;
    trace::mark("child:nnp:done");
    if !rootless {
        syscalls::set_supplementary_groups(supplementary_groups)?;
    }
    trace::mark("child:groups:done");
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
    let Some(resolved) = plan_user_switch(spec, rootless)? else {
        return Ok(());
    };
    if resolved.uid == 0 && resolved.gid == 0 {
        return Ok(());
    }
    // Set gid before uid (the classic order: after setgid, the effective uid is
    // still root, so setuid is still allowed).
    syscalls::set_gid(resolved.gid)
        .map_err(|e| crate::zerr!("setgid({}) failed: {e}", resolved.gid))?;
    syscalls::set_uid(resolved.uid)
        .map_err(|e| crate::zerr!("setuid({}) failed: {e}", resolved.uid))?;
    Ok(())
}

/// Resolve the requested identity and decide whether the rootless pre-existing
/// uid/gid 0 mapping needs no further switch.
fn plan_user_switch(spec: Option<&str>, rootless: bool) -> ZResult<Option<ResolvedUser>> {
    let resolved = match spec {
        Some(raw) => resolve_user_spec(raw)?,
        None => ResolvedUser { uid: 0, gid: 0 },
    };
    if rootless {
        if resolved.uid != 0 || resolved.gid != 0 {
            return Err(crate::zerr!(
                "rootless containers map only uid/gid 0; cannot switch to '{}' (use --user 0 or run rootful)",
                spec.unwrap_or("0")
            ));
        }
        return Ok(None);
    }
    Ok(Some(resolved))
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

    let (uid, primary_gid) = match parse_id(user_part) {
        Some(id) => (id, id),
        None => lookup_user_uid_gid(user_part)?
            .ok_or_else(|| crate::zerr!("unknown user '{user_part}' in container /etc/passwd"))?,
    };
    let gid = match group_part {
        Some(group) => {
            if group.is_empty() {
                return Err(crate::zerr!("invalid --user '{raw}' (empty group)"));
            }
            match parse_id(group) {
                Some(id) => id,
                None => lookup_group_gid(group)?.ok_or_else(|| {
                    crate::zerr!("unknown group '{group}' in container /etc/group")
                })?,
            }
        }
        None => primary_gid,
    };
    Ok(ResolvedUser { uid, gid })
}

/// Split Docker-style `--group-add` values into validated, canonical entries.
///
/// Commas are accepted because Docker's string-slice flag treats them as
/// repeated values. Numeric ids are normalized before persistence so `0043` and
/// `43` cannot create duplicate state entries.
pub fn parse_group_add_values(raw: &str) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    for part in raw.split(',') {
        let value = part.trim();
        if value.is_empty() {
            return Err("group name or id cannot be empty".to_string());
        }
        if value.len() > 255 {
            return Err(format!("group name or id '{value}' is too long"));
        }
        if value.contains(':')
            || value
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err(format!(
                "invalid group '{value}' (expected a name from /etc/group or a numeric gid)"
            ));
        }
        let canonical = if value.bytes().all(|byte| byte.is_ascii_digit()) {
            value
                .parse::<u32>()
                .map_err(|_| format!("group id '{value}' exceeds the gid range"))?
                .to_string()
        } else {
            if value.starts_with('-') || value.starts_with('+') {
                return Err(format!("invalid group id '{value}'"));
            }
            value.to_string()
        };
        if !values.contains(&canonical) {
            values.push(canonical);
        }
    }
    Ok(values)
}

/// Resolve additional group names against the container's `/etc/group`.
///
/// The caller must already be inside the container mount namespace. Rootless
/// user namespaces map only gid 0 and deny `setgroups`, so any addition fails
/// explicitly instead of producing a silently incomplete group set.
pub fn resolve_group_additions(specs: &[String], rootless: bool) -> ZResult<Vec<u32>> {
    if specs.is_empty() {
        return Ok(Vec::new());
    }
    if rootless {
        return Err(crate::zerr!(
            "--group-add is unavailable in rootless mode; run rootful"
        ));
    }
    let mut groups = BTreeSet::new();
    for spec in specs {
        let gid = match parse_id(spec) {
            Some(gid) => gid,
            None => lookup_group_gid(spec)?.ok_or_else(|| {
                crate::zerr!("unknown --group-add '{spec}' in container /etc/group")
            })?,
        };
        groups.insert(gid);
    }
    Ok(groups.into_iter().collect())
}

fn parse_id(value: &str) -> Option<u32> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

// Account databases come from the container image. Bound reads and avoid
// blocking on FIFOs or reading devices while still allowing regular symlinks.
const MAX_ACCOUNT_FILE_BYTES: u64 = 8 * 1024 * 1024;

fn read_account_file(path: &Path) -> ZResult<Option<String>> {
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(crate::zerr!("open {}: {error}", path.display())),
    };
    let metadata = file
        .metadata()
        .map_err(|error| crate::zerr!("inspect {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(crate::zerr!("{} is not a regular file", path.display()));
    }
    let mut bytes = Vec::new();
    file.take(MAX_ACCOUNT_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| crate::zerr!("read {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_ACCOUNT_FILE_BYTES {
        return Err(crate::zerr!(
            "{} exceeds the {} byte limit",
            path.display(),
            MAX_ACCOUNT_FILE_BYTES
        ));
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| crate::zerr!("{} is not valid UTF-8", path.display()))
}

fn lookup_user_uid_gid(name: &str) -> ZResult<Option<(u32, u32)>> {
    let Some(text) = read_account_file(Path::new("/etc/passwd"))? else {
        return Ok(None);
    };
    for line in text.lines() {
        let mut fields = line.split(':');
        if fields.next() == Some(name) {
            let _ = fields.next();
            let uid = fields.next().and_then(|value| value.parse().ok());
            let gid = fields.next().and_then(|value| value.parse().ok());
            return Ok(uid.zip(gid));
        }
    }
    Ok(None)
}

fn lookup_group_gid(name: &str) -> ZResult<Option<u32>> {
    let Some(text) = read_account_file(Path::new("/etc/group"))? else {
        return Ok(None);
    };
    for line in text.lines() {
        let mut fields = line.split(':');
        if fields.next() == Some(name) {
            let _ = fields.next();
            return Ok(fields.next().and_then(|value| value.parse().ok()));
        }
    }
    Ok(None)
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
    syscalls::set_capabilities(lo, hi)
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
    fn account_files_are_bounded_and_must_be_regular() {
        let dir = std::env::temp_dir().join(format!(
            "zerun-account-file-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("passwd");
        assert!(read_account_file(&path).unwrap().is_none());
        std::fs::write(&path, b"alice:x:42:43::/:/bin/sh\n").unwrap();
        assert!(read_account_file(&path)
            .unwrap()
            .unwrap()
            .starts_with("alice:"));
        let link = dir.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_account_file(&link).unwrap().is_some());
        std::fs::write(&path, [0xff]).unwrap();
        assert!(read_account_file(&path)
            .unwrap_err()
            .to_string()
            .contains("UTF-8"));
        std::fs::File::create(&path)
            .unwrap()
            .set_len(MAX_ACCOUNT_FILE_BYTES + 1)
            .unwrap();
        assert!(read_account_file(&path)
            .unwrap_err()
            .to_string()
            .contains("limit"));
        assert!(read_account_file(Path::new("/dev/null"))
            .unwrap_err()
            .to_string()
            .contains("regular file"));
        let fifo = dir.join("fifo");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        assert!(read_account_file(&fifo)
            .unwrap_err()
            .to_string()
            .contains("regular file"));
        std::fs::remove_dir_all(dir).unwrap();
    }

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

    #[test]
    fn group_add_values_are_validated_canonicalized_and_deduplicated() {
        assert_eq!(
            parse_group_add_values("staff,0044, 44,1001").unwrap(),
            vec!["staff", "44", "1001"]
        );
        for value in ["", "staff,", "staff:100", "-1", "+1", "a b", "4294967296"] {
            assert!(parse_group_add_values(value).is_err(), "{value}");
        }
        assert!(resolve_group_additions(&[], true).unwrap().is_empty());
        assert!(resolve_group_additions(&["0".to_string()], true).is_err());
        assert!(resolve_group_additions(&["1".to_string()], true).is_err());
    }

    #[test]
    fn rootful_and_rootless_root_planning_is_explicit() {
        assert_eq!(
            plan_user_switch(None, false).unwrap(),
            Some(ResolvedUser { uid: 0, gid: 0 })
        );
        assert_eq!(
            plan_user_switch(Some("0:0"), false).unwrap(),
            Some(ResolvedUser { uid: 0, gid: 0 })
        );
        assert_eq!(plan_user_switch(None, true).unwrap(), None);
        assert_eq!(plan_user_switch(Some("root"), true).unwrap(), None);
        assert!(plan_user_switch(Some("1000:1000"), true).is_err());
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
