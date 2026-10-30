//! Linux signal names shared by lifecycle options and image configuration.

/// Default signal used by `zerun stop` when neither the image nor the operator
/// selected one.
pub const DEFAULT_STOP_SIGNAL: i32 = libc::SIGTERM;

/// Parse a Linux signal name (with or without `SIG`) or a number in 1..=64.
///
/// Signal 0 is deliberately rejected: it probes a process instead of
/// delivering a signal and is not meaningful for container lifecycle requests.
pub fn parse(raw: &str) -> Result<i32, String> {
    let value = raw.trim();
    if let Ok(signal) = value.parse::<i32>() {
        return validate(signal).map_err(|_| invalid(raw));
    }
    let upper = value.to_ascii_uppercase();
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    // Preserve the spelling accepted by earlier `zerun kill --signal` builds.
    let name = name.strip_prefix('-').unwrap_or(name);
    let signal = match name {
        "HUP" => libc::SIGHUP,
        "INT" => libc::SIGINT,
        "QUIT" => libc::SIGQUIT,
        "ILL" => libc::SIGILL,
        "TRAP" => libc::SIGTRAP,
        "ABRT" | "IOT" => libc::SIGABRT,
        "BUS" => libc::SIGBUS,
        "FPE" => libc::SIGFPE,
        "KILL" => libc::SIGKILL,
        "USR1" => libc::SIGUSR1,
        "SEGV" => libc::SIGSEGV,
        "USR2" => libc::SIGUSR2,
        "PIPE" => libc::SIGPIPE,
        "ALRM" => libc::SIGALRM,
        "TERM" => libc::SIGTERM,
        "STKFLT" => libc::SIGSTKFLT,
        "CHLD" | "CLD" => libc::SIGCHLD,
        "CONT" => libc::SIGCONT,
        "STOP" => libc::SIGSTOP,
        "TSTP" => libc::SIGTSTP,
        "TTIN" => libc::SIGTTIN,
        "TTOU" => libc::SIGTTOU,
        "URG" => libc::SIGURG,
        "XCPU" => libc::SIGXCPU,
        "XFSZ" => libc::SIGXFSZ,
        "VTALRM" => libc::SIGVTALRM,
        "PROF" => libc::SIGPROF,
        "WINCH" => libc::SIGWINCH,
        "IO" | "POLL" => libc::SIGIO,
        "PWR" => libc::SIGPWR,
        "SYS" => libc::SIGSYS,
        _ => return Err(invalid(raw)),
    };
    Ok(signal)
}

/// Validate an already-parsed signal number.
pub fn validate(signal: i32) -> Result<i32, String> {
    if (1..=64).contains(&signal) {
        Ok(signal)
    } else {
        Err(format!("signal number {signal} is outside 1-64"))
    }
}

/// Canonical `SIG...` spelling for persisted state and reconstructed commands.
pub fn name(signal: i32) -> String {
    let name = match signal {
        libc::SIGHUP => "HUP",
        libc::SIGINT => "INT",
        libc::SIGQUIT => "QUIT",
        libc::SIGILL => "ILL",
        libc::SIGTRAP => "TRAP",
        libc::SIGABRT => "ABRT",
        libc::SIGBUS => "BUS",
        libc::SIGFPE => "FPE",
        libc::SIGKILL => "KILL",
        libc::SIGUSR1 => "USR1",
        libc::SIGSEGV => "SEGV",
        libc::SIGUSR2 => "USR2",
        libc::SIGPIPE => "PIPE",
        libc::SIGALRM => "ALRM",
        libc::SIGTERM => "TERM",
        libc::SIGSTKFLT => "STKFLT",
        libc::SIGCHLD => "CHLD",
        libc::SIGCONT => "CONT",
        libc::SIGSTOP => "STOP",
        libc::SIGTSTP => "TSTP",
        libc::SIGTTIN => "TTIN",
        libc::SIGTTOU => "TTOU",
        libc::SIGURG => "URG",
        libc::SIGXCPU => "XCPU",
        libc::SIGXFSZ => "XFSZ",
        libc::SIGVTALRM => "VTALRM",
        libc::SIGPROF => "PROF",
        libc::SIGWINCH => "WINCH",
        libc::SIGIO => "IO",
        libc::SIGPWR => "PWR",
        libc::SIGSYS => "SYS",
        _ => return signal.to_string(),
    };
    format!("SIG{name}")
}

fn invalid(raw: &str) -> String {
    format!("invalid signal '{raw}' (expected a Linux signal name or number 1-64)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_names_numbers_and_aliases() {
        assert_eq!(parse("TERM"), Ok(libc::SIGTERM));
        assert_eq!(parse("SIGUSR1"), Ok(libc::SIGUSR1));
        assert_eq!(parse("sig-term"), Ok(libc::SIGTERM));
        assert_eq!(parse(" 9 "), Ok(libc::SIGKILL));
        assert_eq!(parse("64"), Ok(64));
        assert_eq!(parse("CLD"), Ok(libc::SIGCHLD));
        assert_eq!(parse("poll"), Ok(libc::SIGIO));
    }

    #[test]
    fn rejects_zero_out_of_range_and_unknown_names() {
        for raw in ["0", "65", "-1", "SIG", "NOT_A_SIGNAL", ""] {
            assert!(parse(raw).is_err(), "{raw:?} was accepted");
        }
    }

    #[test]
    fn canonical_names_round_trip() {
        for signal in [libc::SIGHUP, libc::SIGINT, libc::SIGKILL, libc::SIGTERM, 64] {
            assert_eq!(parse(&name(signal)), Ok(signal));
        }
        assert_eq!(name(libc::SIGTERM), "SIGTERM");
        assert_eq!(name(64), "64");
    }
}
