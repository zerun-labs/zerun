//! Built-in mini-init (like docker-init/tini).
//!
//! Runs directly as container PID 1 when `--init` is used. Responsibilities:
//!
//! 1. reap orphaned children to avoid zombies;
//! 2. forward lifecycle signals to the workload;
//! 3. exit with the workload's exit code.
//!
//! The `zerun __init -- cmd` re-exec entry is retained for manual/legacy use.
use crate::error::ZResult;
use std::os::fd::RawFd;
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
    run_impl(business, env, hostname, id, None)
}

/// Run mini-init with the namespace setup error pipe still open.
///
/// The workload child inherits `error_w`; a successful exec closes it through
/// O_CLOEXEC, while an exec failure writes the diagnostic there. Mini-init's
/// parent closes its copy after the fork so the runtime parent can distinguish
/// those outcomes. Errors before the fork leave the endpoint for the caller to
/// report through the same pipe.
pub fn run_with_error_pipe(
    business: &[String],
    env: Option<&[(String, String)]>,
    hostname: Option<&str>,
    id: &str,
    error_w: RawFd,
) -> ZResult<i32> {
    run_impl(business, env, hostname, id, Some(error_w))
}

fn run_impl(
    business: &[String],
    env: Option<&[(String, String)]>,
    hostname: Option<&str>,
    id: &str,
    error_w: Option<RawFd>,
) -> ZResult<i32> {
    if business.is_empty() {
        return Err(crate::zerr!("__init: missing business command"));
    }

    // PID 1 is implicitly a subreaper. In a shared host PID namespace it is an
    // ordinary process, so opt in explicitly to keep orphan reaping working.
    crate::syscalls::become_child_subreaper()?;

    // Forward every catchable asynchronous lifecycle signal, including custom
    // STOPSIGNAL values and real-time signals. PID 1 controls the namespace's
    // signal disposition, so forwarding only TERM/INT would make `stop
    // --signal USR1` silently lose the signal whenever `--init` is enabled.
    for signal in forwardable_signals() {
        crate::syscalls::install_signal_handler(signal, forward_signal)?;
    }

    let pid = crate::syscalls::fork_process()
        .map_err(|error| crate::zerr!("fork in mini-init: {error}"))?;
    if pid == 0 {
        // Workload child (container PID 2): restore default signal handling, then exec.
        for signal in forwardable_signals() {
            crate::syscalls::reset_signal_handler(signal)?;
        }
        if let Err(error) = exec_business(business, env, hostname, id) {
            match error_w {
                Some(fd) => {
                    let message = format!("{error}");
                    let _ = crate::syscalls::write_all_fd(fd, message.as_bytes());
                    crate::syscalls::close(fd);
                }
                None => eprintln!("zerun-init: {error}"),
            }
            crate::syscalls::exit_process(1);
        }
        unreachable!("exec failure is reported and exits");
    }
    CHILD_PID.store(pid, Ordering::Relaxed);
    // The workload child now owns the only error-pipe writer. Its successful
    // exec closes it via O_CLOEXEC; an exec failure writes before closing.
    if let Some(fd) = error_w {
        crate::syscalls::close(fd);
    }

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

/// Asynchronous signals forwarded by mini-init. Synchronous faults
/// (SIGSEGV/SIGBUS/...) must keep their default disposition so a real fault in
/// init cannot recurse through the forwarding handler. SIGKILL and SIGSTOP
/// cannot have handlers; SIGCHLD stays with init because it drives reaping.
fn forwardable_signals() -> impl Iterator<Item = libc::c_int> {
    [
        libc::SIGHUP,
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGUSR1,
        libc::SIGUSR2,
        libc::SIGPIPE,
        libc::SIGALRM,
        libc::SIGTERM,
        libc::SIGSTKFLT,
        libc::SIGCONT,
        libc::SIGTSTP,
        libc::SIGTTIN,
        libc::SIGTTOU,
        libc::SIGURG,
        libc::SIGXCPU,
        libc::SIGXFSZ,
        libc::SIGVTALRM,
        libc::SIGPROF,
        libc::SIGWINCH,
        libc::SIGIO,
        libc::SIGPWR,
    ]
    .into_iter()
    .chain(libc::SIGRTMIN()..=libc::SIGRTMAX())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwards_custom_and_realtime_signals_but_not_reaping_signals() {
        let signals: Vec<_> = forwardable_signals().collect();
        assert!(signals.contains(&libc::SIGUSR1));
        assert!(signals.contains(&libc::SIGQUIT));
        assert!(signals.contains(&libc::SIGRTMIN()));
        assert!(signals.contains(&libc::SIGRTMAX()));
        assert!(!signals.contains(&libc::SIGKILL));
        assert!(!signals.contains(&libc::SIGSTOP));
        assert!(!signals.contains(&libc::SIGCHLD));
        assert!(!signals.contains(&libc::SIGSEGV));
        assert!(!signals.contains(&libc::SIGBUS));
    }
}
