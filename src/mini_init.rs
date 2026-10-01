//! Built-in mini-init (like docker-init/tini).
//!
//! Runs directly as container PID 1 when `--init` is used. Responsibilities:
//!
//! 1. reap orphaned children to avoid zombies;
//! 2. forward SIGTERM/SIGINT to the workload;
//! 3. exit with the workload's exit code.
//!
//! The `zerun __init -- cmd` re-exec entry is retained for manual/legacy use.
use crate::error::ZResult;
use std::sync::atomic::{AtomicI32, Ordering};

static CHILD_PID: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward_signal(_sig: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::Relaxed);
    if pid > 0 {
        crate::syscalls::signal_process(pid, _sig);
    }
}

/// Run the business command as a child of this init process.
///
/// `env` is the explicit container environment (image mode); `None` keeps the
/// inherited environment (legacy `--rootfs` mode). `hostname`/`id` feed the
/// HOSTNAME default in legacy mode.
pub fn run(
    business: &[String],
    env: Option<&[(String, String)]>,
    hostname: Option<&str>,
    id: &str,
) -> ZResult<i32> {
    if business.is_empty() {
        return Err(crate::zerr!("__init: missing business command"));
    }

    // Install forwarding handlers. Init itself ignores SIGPIPE/SIGHUP
    // termination semantics; the workload decides how to handle them.
    crate::syscalls::install_signal_handler(libc::SIGTERM, forward_signal)?;
    crate::syscalls::install_signal_handler(libc::SIGINT, forward_signal)?;

    let pid = crate::syscalls::fork_process()
        .map_err(|error| crate::zerr!("fork in mini-init: {error}"))?;
    if pid == 0 {
        // Workload child (container PID 2): restore default signal handling, then exec.
        crate::syscalls::reset_signal_handler(libc::SIGTERM)?;
        crate::syscalls::reset_signal_handler(libc::SIGINT)?;
        exec_business(business, env, hostname, id)?;
        unreachable!("exec failure is returned as Err");
    }
    CHILD_PID.store(pid, Ordering::Relaxed);

    // Reap loop: after the workload exits, keep sweeping orphans with WNOHANG
    // until ECHILD.
    let mut business_code = 0i32;
    let mut business_exited = false;
    loop {
        let (rpid, status) = match crate::syscalls::wait_pid(-1, 0) {
            Ok(Some(result)) => result,
            Ok(None) => continue,
            Err(_) => break, // ECHILD: no children left
        };
        if rpid == pid {
            business_code = decode_status(status);
            business_exited = true;
        }
        if business_exited {
            // Non-blocking sweep for processes that became orphans after the
            // workload exited.
            while matches!(crate::syscalls::wait_pid(-1, libc::WNOHANG), Ok(Some(_))) {}
            break;
        }
    }
    Ok(business_code)
}

fn decode_status(status: libc::c_int) -> i32 {
    crate::syscalls::wait_status_code(status).unwrap_or(1)
}

fn exec_business(
    argv: &[String],
    env: Option<&[(String, String)]>,
    hostname: Option<&str>,
    id: &str,
) -> ZResult<()> {
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    crate::workload::apply_env(&mut cmd, env, hostname, id);
    let err = cmd.exec();
    Err(crate::zerr!("mini-init exec {} failed: {err}", argv[0]))
}
