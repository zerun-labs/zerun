//! Host-side PTY support for `run -t`.
//!
//! The container child receives the PTY slave as stdin/stdout/stderr and makes
//! it its controlling terminal. The foreground CLI remains outside the
//! container's session and pumps bytes between its own terminal (if any) and
//! the PTY master. Raw mode is only enabled for a genuinely bidirectional
//! interactive session; output-only `-t` stays in the caller's terminal mode.

use crate::syscalls;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicI32, Ordering};

/// Restore host terminal settings when an attached PTY session ends.
struct RawTerminalGuard {
    saved: Option<libc::termios>,
}

impl RawTerminalGuard {
    fn attach(master: RawFd, interactive: bool) -> crate::error::ZResult<Self> {
        if syscalls::is_terminal(libc::STDIN_FILENO) {
            syscalls::copy_window_size(libc::STDIN_FILENO, master)?;
            install_resize_handler(master);
            let saved = if interactive {
                Some(syscalls::make_terminal_raw(libc::STDIN_FILENO)?)
            } else {
                None
            };
            Ok(Self { saved })
        } else {
            Ok(Self { saved: None })
        }
    }
}

impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        if let Some(saved) = &self.saved {
            syscalls::restore_terminal(libc::STDIN_FILENO, saved);
        }
        WINCH_MASTER.store(-1, Ordering::Relaxed);
    }
}

static WINCH_MASTER: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_winch(_sig: libc::c_int) {
    let master = WINCH_MASTER.load(Ordering::Relaxed);
    if master >= 0 {
        if let Ok(ws) = syscalls::terminal_window_size(libc::STDIN_FILENO) {
            let _ = syscalls::set_terminal_window_size(master, &ws);
        }
    }
}

fn install_resize_handler(master: RawFd) {
    WINCH_MASTER.store(master, Ordering::Relaxed);
    let _ = syscalls::install_signal_handler(libc::SIGWINCH, on_winch);
}

/// Start the host<->PTY pump in the background.
///
/// Interactive mode pumps both directions and switches the host terminal to
/// raw mode. Output-only mode leaves stdin alone, matching `run -t` without
/// `-i`; the pump stops when the container closes its PTY.
pub fn attach(master: RawFd, interactive: bool) -> std::thread::JoinHandle<()> {
    let guard = if interactive {
        match RawTerminalGuard::attach(master, interactive) {
            Ok(g) => Some(g),
            Err(e) => {
                eprintln!("zerun: warning: failed to attach host terminal: {e}");
                None
            }
        }
    } else {
        None
    };

    std::thread::Builder::new()
        .name("zerun-pty".to_string())
        .stack_size(64 * 1024)
        .spawn(move || {
            pump(master, interactive);
            drop(guard); // restore before the parent reports the container exit
        })
        .expect("spawn zerun-pty")
}

fn pump(master: RawFd, interactive: bool) {
    let mut stdin_open = interactive;
    let mut master_open = true;
    while stdin_open || master_open {
        let mut fds = [
            libc::pollfd {
                fd: libc::STDIN_FILENO,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: master,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        if syscalls::poll_fds(&mut fds, -1).is_err() {
            break;
        }

        if stdin_open && fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let mut buf = [0u8; 8 * 1024];
            match syscalls::read_fd(libc::STDIN_FILENO, &mut buf) {
                Ok(0) | Err(_) => {
                    stdin_open = false;
                    // Closing the master signals EOF/HUP to the container's
                    // controlling terminal without keeping a stalled thread.
                    syscalls::close(master);
                    master_open = false;
                }
                Ok(n) => {
                    if syscalls::write_all_fd(master, &buf[..n as usize]).is_err() {
                        return;
                    }
                }
            }
        }

        if master_open && fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let mut buf = [0u8; 8 * 1024];
            match syscalls::read_fd(master, &mut buf) {
                Ok(0) | Err(_) => {
                    // The container's PTY is gone; no further stdin has a
                    // destination, so stop the pump immediately.
                    master_open = false;
                    stdin_open = false;
                }
                Ok(n) => {
                    if syscalls::write_all_fd(libc::STDOUT_FILENO, &buf[..n as usize]).is_err() {
                        syscalls::close(master);
                        return;
                    }
                }
            }
        }
    }
}
