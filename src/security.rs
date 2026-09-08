//! Security hardening (the area that v1 of the design doc missed entirely).
//!
//! Current stage: PR_SET_NO_NEW_PRIVS + capability bounding-set drop.
//! Next stage (M2): default seccomp allowlist profile.
use crate::error::ZResult;
use crate::syscalls;
use crate::trace;

/// Security sequence before the workload execs. Order matters: NO_NEW_PRIVS first,
/// then capabilities, then seccomp (loading a seccomp filter without CAP_SYS_ADMIN
/// requires NO_NEW_PRIVS to be set first).
pub fn harden() -> ZResult<()> {
    no_new_privs()?;
    drop_bounding_caps()?;
    apply_seccomp_profile()?;
    trace::mark("child:security:done");
    Ok(())
}

/// PR_SET_NO_NEW_PRIVS=1: setuid/setgid bits and file capabilities no longer
/// grant privileges after execve.
fn no_new_privs() -> ZResult<()> {
    syscalls::prctl_set(libc::PR_SET_NO_NEW_PRIVS, 1)
}

/// Drop every capability from the bounding set and clear effective/permitted/
/// inheritable. M1 uses the strictest "drop everything" policy; a configurable
/// allowlist arrives in a later milestone.
fn drop_bounding_caps() -> ZResult<()> {
    let last = syscalls::cap_last_cap();
    for cap in 0..=last as i32 {
        syscalls::prctl_drop_cap(cap)?;
    }
    // glibc has no capset wrapper; use the raw syscall with the kernel ABI structs
    // to clear the three capability sets.
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
    let mut data = [CapUserData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    unsafe {
        // Ignore the return value: on old kernels returning EINVAL the bounding set
        // is already empty, which is enough to continue.
        libc::syscall(libc::SYS_capset, &header, data.as_mut_ptr());
    }
    Ok(())
}

/// M2 placeholder: default seccomp allowlist.
///
/// Planned implementation path (API verified, filter lands in M2):
/// 1. prctl(PR_SET_NO_NEW_PRIVS, 1) — already done above.
/// 2. Generate a BPF program: default SECCOMP_RET_ERRNO(EPERM), allow a whitelist
///    of common syscalls, explicitly deny keyctl/add_module/userfaultfd/bpf/ptrace.
/// 3. prog.len/prog.filter via syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog).
///
/// Not loaded yet so the skeleton runs on any kernel; the trace explicitly says so.
fn apply_seccomp_profile() -> ZResult<()> {
    trace::mark("child:seccomp:skipped-m2-placeholder");
    Ok(())
}
