//! Default seccomp profile (M2 security milestone).
//!
//! A deny-by-default BPF allowlist is installed right before the workload execs:
//! anything not explicitly allowed returns EPERM, and a non-native architecture
//! is killed. The BPF program is tiny (one JEQ per allowed syscall + epilogue),
//! well under the kernel's 4096-instruction limit.
//!
//! Architecture support is incremental: the allowlist table currently covers
//! x86_64 only. On other targets `SeccompMode::Default` degrades to an explicit
//! error (use `--seccomp unconfined`); add tables in `default_allowlist()` as
//! cross targets are brought up.
use crate::error::ZResult;
use crate::trace;

// --- BPF / seccomp ABI constants ---------------------------------------------
// Stable Linux UAPI values; libc does not export the BPF_* macros.
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_SET_MODE_FILTER: u32 = 1;
const EPERM: u32 = 1;

// offsetof(struct seccomp_data, nr / arch)
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

// EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_NATIVE: u32 = 0xc000_003e;

#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_NATIVE: u32 = 0xc000_00b7;

#[cfg(all(target_arch = "arm", target_endian = "little"))]
const AUDIT_ARCH_NATIVE: u32 = 0x4000_0028;

#[cfg(target_arch = "riscv64")]
const AUDIT_ARCH_NATIVE: u32 = 0xc000_00f3;

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const libc::sock_filter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SeccompMode {
    /// Deny-by-default allowlist (recommended).
    #[default]
    Default,
    /// No seccomp filter (explicit opt-out for workloads needing blocked syscalls).
    Unconfined,
}

/// Install the requested seccomp policy. `PR_SET_NO_NEW_PRIVS` must already be
/// set (security::harden does this before calling us).
pub fn apply(mode: SeccompMode) -> ZResult<()> {
    if mode == SeccompMode::Unconfined {
        trace::mark("child:seccomp:unconfined");
        return Ok(());
    }
    let insns = build_default_program()?;
    let prog = SockFprog {
        len: insns.len() as u16,
        filter: insns.as_ptr(),
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER as libc::c_long,
            0,
            &prog as *const SockFprog,
        )
    };
    if rc != 0 {
        return Err(crate::error::last_err("seccomp(SECCOMP_SET_MODE_FILTER)"));
    }
    trace::mark("child:seccomp:loaded");
    Ok(())
}

/// Build the BPF program for the default profile.
///
/// Layout:
///   0          LD  W ABS 4            (load arch)
///   1          JEQ K <native>, jt=1   (skip the kill on native arch)
///   2          RET KILL_PROCESS       (non-native arch -> kill)
///   3          LD  W ABS 0            (load syscall nr)
///   4..4+n-1   JEQ K <nr_i>, jt=n-i   (match -> jump to ALLOW)
///   4+n        RET ERRNO|EPERM        (default deny)
///   4+n+1      RET ALLOW
pub fn build_default_program() -> ZResult<Vec<libc::sock_filter>> {
    let allowed = match default_allowlist() {
        Some(list) => list,
        None => {
            return Err(crate::zerr!(
                "default seccomp profile is not implemented for target_arch={:?}; \
                 use --seccomp unconfined",
                std::env::consts::ARCH
            ))
        }
    };
    let n = allowed.len();
    if n > u8::MAX as usize {
        return Err(crate::zerr!(
            "seccomp allowlist too large ({n} entries; max {})",
            u8::MAX
        ));
    }

    let mut insns = Vec::with_capacity(n + 5);
    // Architecture gate.
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET));
    insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, AUDIT_ARCH_NATIVE));
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    // Syscall allowlist.
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));
    for (i, nr) in allowed.iter().enumerate() {
        // Equal -> jump over the remaining compares + the default ERRNO, landing
        // exactly on the final ALLOW (see layout comment).
        insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, (n - i) as u8, 0, *nr));
    }
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM));
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    Ok(insns)
}

fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn bpf_jump(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Syscalls allowed by the default profile.
///
/// Curated from the Linux x86_64 table for typical musl/glibc workloads plus
/// common language runtimes; everything else is denied with EPERM. Privileged
/// and dangerous calls (mount, keyctl, bpf, ptrace, userfaultfd, module
/// loading, reboot, ...) are intentionally absent.
#[cfg(target_arch = "x86_64")]
fn default_allowlist() -> Option<Vec<u32>> {
    // Deliberately unsorted; deduplicated below.
    let raw: &[libc::c_long] = &[
        libc::SYS_access,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_alarm,
        libc::SYS_arch_prctl,
        libc::SYS_bind,
        libc::SYS_brk,
        libc::SYS_capget,
        libc::SYS_capset,
        libc::SYS_chdir,
        libc::SYS_chmod,
        libc::SYS_chown,
        libc::SYS_clock_getres,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_close,
        libc::SYS_close_range,
        libc::SYS_connect,
        libc::SYS_copy_file_range,
        libc::SYS_creat,
        libc::SYS_dup,
        libc::SYS_dup2,
        libc::SYS_dup3,
        libc::SYS_epoll_create,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_pwait,
        libc::SYS_epoll_wait,
        libc::SYS_eventfd,
        libc::SYS_eventfd2,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_fallocate,
        libc::SYS_fchdir,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        libc::SYS_fchown,
        libc::SYS_fchownat,
        libc::SYS_fcntl,
        libc::SYS_fdatasync,
        libc::SYS_fgetxattr,
        libc::SYS_flistxattr,
        libc::SYS_flock,
        libc::SYS_fork,
        libc::SYS_fremovexattr,
        libc::SYS_fsetxattr,
        libc::SYS_fstat,
        libc::SYS_fstatfs,
        libc::SYS_fsync,
        libc::SYS_ftruncate,
        libc::SYS_futex,
        libc::SYS_getcpu,
        libc::SYS_getcwd,
        libc::SYS_getdents,
        libc::SYS_getdents64,
        libc::SYS_getegid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getgroups,
        libc::SYS_getitimer,
        libc::SYS_getpeername,
        libc::SYS_getpgid,
        libc::SYS_getpgrp,
        libc::SYS_getpid,
        libc::SYS_getppid,
        libc::SYS_getpriority,
        libc::SYS_getrandom,
        libc::SYS_getresgid,
        libc::SYS_getresuid,
        libc::SYS_getrlimit,
        libc::SYS_getrusage,
        libc::SYS_getsid,
        libc::SYS_getsockname,
        libc::SYS_getsockopt,
        libc::SYS_gettid,
        libc::SYS_gettimeofday,
        libc::SYS_getuid,
        libc::SYS_getxattr,
        libc::SYS_inotify_add_watch,
        libc::SYS_inotify_init,
        libc::SYS_inotify_init1,
        libc::SYS_inotify_rm_watch,
        libc::SYS_ioctl,
        libc::SYS_kill,
        libc::SYS_lchown,
        libc::SYS_lgetxattr,
        libc::SYS_link,
        libc::SYS_linkat,
        libc::SYS_listen,
        libc::SYS_listxattr,
        libc::SYS_llistxattr,
        libc::SYS_lremovexattr,
        libc::SYS_lseek,
        libc::SYS_lsetxattr,
        libc::SYS_lstat,
        libc::SYS_madvise,
        libc::SYS_memfd_create,
        libc::SYS_mincore,
        libc::SYS_mkdir,
        libc::SYS_mkdirat,
        libc::SYS_mknod,
        libc::SYS_mknodat,
        libc::SYS_mlock,
        libc::SYS_mlock2,
        libc::SYS_mlockall,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_mq_getsetattr,
        libc::SYS_mq_notify,
        libc::SYS_mq_open,
        libc::SYS_mq_timedreceive,
        libc::SYS_mq_timedsend,
        libc::SYS_mq_unlink,
        libc::SYS_mremap,
        libc::SYS_msgctl,
        libc::SYS_msgget,
        libc::SYS_msgrcv,
        libc::SYS_msgsnd,
        libc::SYS_msync,
        libc::SYS_munlock,
        libc::SYS_munlockall,
        libc::SYS_munmap,
        libc::SYS_name_to_handle_at,
        libc::SYS_nanosleep,
        libc::SYS_newfstatat,
        libc::SYS_open,
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_pause,
        libc::SYS_personality,
        libc::SYS_pipe,
        libc::SYS_pipe2,
        libc::SYS_poll,
        libc::SYS_ppoll,
        libc::SYS_prctl,
        libc::SYS_pread64,
        libc::SYS_preadv,
        libc::SYS_prlimit64,
        libc::SYS_pselect6,
        libc::SYS_pwrite64,
        libc::SYS_pwritev,
        libc::SYS_read,
        libc::SYS_readlink,
        libc::SYS_readlinkat,
        libc::SYS_readv,
        libc::SYS_recvfrom,
        libc::SYS_recvmmsg,
        libc::SYS_recvmsg,
        libc::SYS_removexattr,
        libc::SYS_rename,
        libc::SYS_renameat,
        libc::SYS_renameat2,
        libc::SYS_restart_syscall,
        libc::SYS_rmdir,
        libc::SYS_rseq,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigpending,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigqueueinfo,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigsuspend,
        libc::SYS_rt_sigtimedwait,
        libc::SYS_rt_tgsigqueueinfo,
        libc::SYS_sched_getaffinity,
        libc::SYS_sched_getattr,
        libc::SYS_sched_getparam,
        libc::SYS_sched_getscheduler,
        libc::SYS_sched_rr_get_interval,
        libc::SYS_sched_setaffinity,
        libc::SYS_sched_setattr,
        libc::SYS_sched_setparam,
        libc::SYS_sched_setscheduler,
        libc::SYS_sched_yield,
        libc::SYS_select,
        libc::SYS_semctl,
        libc::SYS_semget,
        libc::SYS_semop,
        libc::SYS_semtimedop,
        libc::SYS_sendfile,
        libc::SYS_sendmmsg,
        libc::SYS_sendmsg,
        libc::SYS_sendto,
        libc::SYS_set_robust_list,
        libc::SYS_setfsgid,
        libc::SYS_setfsuid,
        libc::SYS_setgid,
        libc::SYS_setgroups,
        libc::SYS_setitimer,
        libc::SYS_setpgid,
        libc::SYS_setpriority,
        libc::SYS_setregid,
        libc::SYS_setresgid,
        libc::SYS_setresuid,
        libc::SYS_setreuid,
        libc::SYS_setsid,
        libc::SYS_setsockopt,
        libc::SYS_setuid,
        libc::SYS_setxattr,
        libc::SYS_shmat,
        libc::SYS_shmctl,
        libc::SYS_shmdt,
        libc::SYS_shmget,
        libc::SYS_shutdown,
        libc::SYS_sigaltstack,
        libc::SYS_signalfd,
        libc::SYS_signalfd4,
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_splice,
        libc::SYS_stat,
        libc::SYS_statfs,
        libc::SYS_statx,
        libc::SYS_symlink,
        libc::SYS_symlinkat,
        libc::SYS_sync,
        libc::SYS_sync_file_range,
        libc::SYS_syncfs,
        libc::SYS_sysinfo,
        libc::SYS_tee,
        libc::SYS_tgkill,
        libc::SYS_time,
        libc::SYS_timer_create,
        libc::SYS_timer_delete,
        libc::SYS_timer_getoverrun,
        libc::SYS_timer_gettime,
        libc::SYS_timer_settime,
        libc::SYS_timerfd_create,
        libc::SYS_timerfd_gettime,
        libc::SYS_timerfd_settime,
        libc::SYS_times,
        libc::SYS_tkill,
        libc::SYS_truncate,
        libc::SYS_umask,
        libc::SYS_uname,
        libc::SYS_unlink,
        libc::SYS_unlinkat,
        libc::SYS_unshare,
        libc::SYS_utime,
        libc::SYS_utimensat,
        libc::SYS_utimes,
        libc::SYS_vfork,
        libc::SYS_vmsplice,
        libc::SYS_wait4,
        libc::SYS_waitid,
        libc::SYS_write,
        libc::SYS_writev,
    ];
    let mut list: Vec<u32> = raw.iter().map(|&nr| nr as u32).collect();
    list.sort_unstable();
    list.dedup();
    Some(list)
}

#[cfg(not(target_arch = "x86_64"))]
fn default_allowlist() -> Option<Vec<u32>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code_of(i: &libc::sock_filter) -> u16 {
        i.code
    }

    fn k_of(i: &libc::sock_filter) -> u32 {
        i.k
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn program_structure_is_sane() {
        let p = build_default_program().unwrap();
        assert!(p.len() <= 4096, "BPF program exceeds kernel limit");
        // [0] load arch, [1] jeq native arch, [2] kill, [3] load nr.
        assert_eq!(code_of(&p[0]), BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(k_of(&p[0]), SECCOMP_DATA_ARCH_OFFSET);
        assert_eq!(code_of(&p[1]), BPF_JMP | BPF_JEQ | BPF_K);
        assert_eq!(k_of(&p[1]), AUDIT_ARCH_NATIVE);
        assert_eq!(code_of(&p[2]), BPF_RET | BPF_K);
        assert_eq!(k_of(&p[2]), SECCOMP_RET_KILL_PROCESS);
        assert_eq!(code_of(&p[3]), BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(k_of(&p[3]), SECCOMP_DATA_NR_OFFSET);

        // Epilogue: default ERRNO then ALLOW.
        let last = p.len() - 1;
        assert_eq!(code_of(&p[last]), BPF_RET | BPF_K);
        assert_eq!(k_of(&p[last]), SECCOMP_RET_ALLOW);
        assert_eq!(code_of(&p[last - 1]), BPF_RET | BPF_K);
        assert_eq!(k_of(&p[last - 1]), SECCOMP_RET_ERRNO | EPERM);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn every_allowed_syscall_is_present_and_jump_lands_on_allow() {
        let p = build_default_program().unwrap();
        let allowed = default_allowlist().unwrap();
        let allow_idx = (p.len() - 1) as usize;
        // Compare block: p[4 .. 4+n); each must JEQ an allowlisted nr and its
        // jt must land exactly on the ALLOW instruction.
        for (i, insn) in p.iter().enumerate().skip(4).take(allowed.len()) {
            assert_eq!(
                code_of(insn),
                BPF_JMP | BPF_JEQ | BPF_K,
                "insn {i} not a JEQ"
            );
            assert!(allowed.binary_search(&k_of(insn)).is_ok());
            let target = i + 1 + insn.jt as usize;
            assert_eq!(target, allow_idx, "jump from insn {i} misses ALLOW");
        }
        // And the default-ERRNO instruction sits between the compares and ALLOW.
        assert_eq!(p.len(), 4 + allowed.len() + 2);
    }
}
