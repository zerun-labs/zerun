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
    no_new_privs()?;
    apply_capabilities(DEFAULT_CAPS)?;
    seccomp::apply(seccomp_mode)?;
    trace::mark("child:security:done");
    Ok(())
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
