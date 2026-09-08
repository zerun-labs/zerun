//! Built-in mini-init (like docker-init/tini).
//!
//! Entered by the container init process via `zerun __init -- <cmd>...` re-exec.
//! Responsibilities: 1) reap orphaned children to avoid zombies; 2) forward
//! SIGTERM/SIGINT to the workload; 3) exit with the workload's exit code.
use crate::error::{last_err, ZResult};
use std::sync::atomic::{AtomicI32, Ordering};

static CHILD_PID: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward_signal(_sig: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::Relaxed);
    if pid > 0 {
        unsafe {
            libc::kill(pid, _sig);
        }
    }
}

/// `argv` is the business command after `--` in `__init -- <cmd> ...`.
pub fn run(business: &[String]) -> ZResult<i32> {
    if business.is_empty() {
        return Err(crate::zerr!("__init: missing business command"));
    }

    // Install forwarding handlers.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = forward_signal as extern "C" fn(libc::c_int) as usize;
        libc::sigemptyset(&mut sa.sa_mask as *mut libc::sigset_t);
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        // init itself ignores SIGPIPE/SIGHUP termination semantics; the workload
        // decides how to handle them.
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(last_err("fork in mini-init"));
    }
    if pid == 0 {
        // Workload child (container PID 2): restore default signal handling, then exec.
        unsafe {
            libc::signal(libc::SIGTERM, libc::SIG_DFL);
            libc::signal(libc::SIGINT, libc::SIG_DFL);
        }
        exec_business(business)?;
        unreachable!("exec failure is returned as Err");
    }
    CHILD_PID.store(pid, Ordering::Relaxed);

    // Reap loop: after the workload exits, keep sweeping orphans with WNOHANG
    // until ECHILD.
    let mut business_code = 0i32;
    let mut business_exited = false;
    loop {
        let mut status: libc::c_int = 0;
        let rpid = unsafe { libc::waitpid(-1, &mut status, 0) };
        if rpid < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break; // ECHILD: no children left
        }
        if rpid == pid {
            business_code = decode_status(status);
            business_exited = true;
        }
        if business_exited {
            // Non-blocking sweep for processes that became orphans after the
            // workload exited.
            while unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) } > 0 {}
            break;
        }
    }
    Ok(business_code)
}

fn decode_status(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}

fn exec_business(argv: &[String]) -> ZResult<()> {
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    // Container-conventional default PATH, consistent with the direct-exec path.
    cmd.env(
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    );
    let err = cmd.exec();
    Err(crate::zerr!("mini-init exec {} failed: {err}", argv[0]))
}
