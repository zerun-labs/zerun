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

/// Linux capability numbers (stable ABI; the libc crate does not expose them).
mod cap {
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

/// Security sequence before the workload execs. Order matters: NO_NEW_PRIVS first,
/// then capabilities, then seccomp (loading a seccomp filter without CAP_SYS_ADMIN
/// requires NO_NEW_PRIVS to be set first).
pub fn harden(seccomp_mode: SeccompMode) -> ZResult<()> {
    trace::mark("child:security:begin");
    no_new_privs()?;
    trace::mark("child:nnp:done");
    apply_capabilities(DEFAULT_CAPS)?;
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
fn apply_capabilities(keep: &[i32]) -> ZResult<()> {
    let (lo, hi) = keep_mask(keep);
    let last = syscalls::cap_last_cap();
    for cap in 0..=last as i32 {
        if !keep.contains(&cap) {
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
fn keep_mask(keep: &[i32]) -> (u32, u32) {
    let mut lo = 0u32;
    let mut hi = 0u32;
    for &c in keep {
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
