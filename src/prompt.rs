//! Owner-side credential prompts.
//!
//! Reading a password directly avoids putting secrets in process arguments. A
//! controlling terminal gets echo disabled; scripts should use
//! `--password-stdin` rather than non-terminal password prompts.

use crate::error::ZResult;
use std::io::{BufRead, Read, Write};

/// Prompt for and read a username. An existing value short-circuits the prompt.
pub fn username(value: Option<String>) -> ZResult<String> {
    if let Some(v) = value {
        return Ok(v);
    }
    print!("Username: ");
    std::io::stdout()
        .flush()
        .map_err(|e| crate::zerr!("write username prompt: {e}"))?;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| crate::zerr!("read username: {e}"))?;
    let username = line.trim();
    if username.is_empty() {
        return Err(crate::zerr!("username is required"));
    }
    Ok(username.to_string())
}

/// Read a password from stdin (normally `--password-stdin`).
pub fn password_from_stdin() -> ZResult<String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .read_to_end(&mut bytes)
        .map_err(|e| crate::zerr!("read password stdin: {e}"))?;
    let password = strip_newline(&bytes);
    String::from_utf8(password).map_err(|_| crate::zerr!("password stdin is not UTF-8"))
}

/// Read a password from stdin with terminal echo disabled when possible.
pub fn password_interactive() -> ZResult<String> {
    if !crate::syscalls::is_terminal(libc::STDIN_FILENO) {
        return Err(crate::zerr!(
            "stdin is not a terminal; use --password-stdin for scripted login"
        ));
    }

    print!("Password: ");
    std::io::stdout()
        .flush()
        .map_err(|e| crate::zerr!("write password prompt: {e}"))?;
    let saved = crate::syscalls::disable_terminal_echo(libc::STDIN_FILENO)?;
    let mut bytes = Vec::new();
    let result = std::io::stdin().lock().read_until(b'\n', &mut bytes);
    // Always restore the caller's terminal, including after a read error.
    crate::syscalls::restore_terminal(libc::STDIN_FILENO, &saved);
    println!();
    result.map_err(|e| crate::zerr!("read password: {e}"))?;
    let password = strip_newline(&bytes);
    if password.is_empty() {
        return Err(crate::zerr!("password is required"));
    }
    String::from_utf8(password).map_err(|_| crate::zerr!("password is not UTF-8"))
}

fn strip_newline(bytes: &[u8]) -> Vec<u8> {
    let mut v = bytes.to_vec();
    if v.last() == Some(&b'\n') {
        v.pop();
    }
    if v.last() == Some(&b'\r') {
        v.pop();
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_one_terminal_newline() {
        assert_eq!(strip_newline(b"secret\n"), b"secret");
        assert_eq!(strip_newline(b"secret\r\n"), b"secret");
        assert_eq!(strip_newline(b"secret"), b"secret");
        assert_eq!(strip_newline(b"secret\n\n"), b"secret\n");
    }

    #[test]
    fn existing_username_wins_without_reading_stdin() {
        assert_eq!(username(Some("alice".into())).unwrap(), "alice");
    }
}
