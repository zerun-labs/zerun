//! Docker-compatible container health checks.
//!
//! Health probes are optional stateful work on top of the daemonless lifecycle:
//! the detached reaper forks one tiny monitor for each workload attempt, and
//! that monitor executes the configured command through the same namespace,
//! cgroup, user, capability, seccomp, and environment setup as `zerun exec`.
//! Results are persisted atomically in `state.json`; there is no resident
//! health daemon and no second control plane.
use crate::error::ZResult;
use crate::state::{self, ContainerState, HealthLog, HealthState, HealthStatus, Status};
use crate::store::Store;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

pub const DEFAULT_INTERVAL_NS: u64 = 30_000_000_000;
pub const DEFAULT_TIMEOUT_NS: u64 = 30_000_000_000;
pub const DEFAULT_START_INTERVAL_NS: u64 = 5_000_000_000;
pub const DEFAULT_RETRIES: u32 = 3;
pub const DEFAULT_START_PERIOD_NS: u64 = 0;

const MAX_HEALTH_LOG_ENTRIES: usize = 5;
const MAX_PROBE_OUTPUT_BYTES: usize = 4096;
const MONITOR_STOP_TIMEOUT: Duration = Duration::from_secs(2);
const MONITOR_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Persisted healthcheck configuration for one container.
///
/// Durations are nanoseconds to match the Docker/OCI image-config JSON
/// representation. `test` retains Docker's command form (`CMD` or
/// `CMD-SHELL`) until probe time so configuration errors are detected before
/// the workload starts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Healthcheck {
    pub test: Vec<String>,
    pub interval_ns: u64,
    pub timeout_ns: u64,
    pub start_period_ns: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_interval_ns: Option<u64>,
    pub retries: u32,
}

impl Healthcheck {
    pub fn new(test: Vec<String>) -> Result<Self, String> {
        let check = Self {
            test,
            interval_ns: DEFAULT_INTERVAL_NS,
            timeout_ns: DEFAULT_TIMEOUT_NS,
            start_period_ns: DEFAULT_START_PERIOD_NS,
            start_interval_ns: None,
            retries: DEFAULT_RETRIES,
        };
        check.validate()?;
        Ok(check)
    }

    /// Validate and normalize the command form without executing it.
    pub fn validate(&self) -> Result<(), String> {
        validate_test(&self.test)?;
        if self.interval_ns == 0 {
            return Err("healthcheck interval must be greater than zero".to_string());
        }
        if self.timeout_ns == 0 {
            return Err("healthcheck timeout must be greater than zero".to_string());
        }
        if self.retries == 0 {
            return Err("healthcheck retries must be greater than zero".to_string());
        }
        for (name, value) in [
            ("interval", Some(self.interval_ns)),
            ("timeout", Some(self.timeout_ns)),
            ("start period", Some(self.start_period_ns)),
            ("start interval", self.start_interval_ns),
        ] {
            if value.is_some_and(|value| value > i64::MAX as u64) {
                return Err(format!(
                    "healthcheck {name} exceeds the image-config duration range"
                ));
            }
        }
        if self.start_interval_ns == Some(0) {
            return Err(
                "healthcheck start interval must be greater than zero when set".to_string(),
            );
        }
        Ok(())
    }

    /// Encode this check in Docker's OCI image-config extension form.
    pub fn to_image(&self) -> Result<ImageHealthcheck, String> {
        self.validate()?;
        let duration = |value: u64| -> Result<i64, String> {
            i64::try_from(value).map_err(|_| "healthcheck duration is too large".to_string())
        };
        Ok(ImageHealthcheck {
            test: Some(self.test.clone()),
            interval: Some(duration(self.interval_ns)?),
            timeout: Some(duration(self.timeout_ns)?),
            start_period: Some(duration(self.start_period_ns)?),
            start_interval: self.start_interval_ns.map(duration).transpose()?,
            retries: Some(i64::from(self.retries)),
        })
    }

    /// Convert the configured command into the argv passed to the container.
    pub fn command_argv(&self) -> Result<Vec<String>, String> {
        self.validate()?;
        let kind = self.test.first().map(String::as_str).unwrap_or("");
        match kind {
            "CMD-SHELL" => Ok(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                self.test[1].clone(),
            ]),
            "CMD" => Ok(self.test[1..].to_vec()),
            other => Err(format!("invalid healthcheck command type '{other}'")),
        }
    }

    fn in_start_period(&self, elapsed: Duration) -> bool {
        self.start_period_ns > 0 && elapsed < Duration::from_nanos(self.start_period_ns)
    }

    fn delay_for(&self, health: Option<&HealthState>, in_start_period: bool) -> Duration {
        let ns = match health.map(|health| health.status) {
            Some(HealthStatus::Starting) | None if in_start_period => {
                self.start_interval_ns.unwrap_or(DEFAULT_START_INTERVAL_NS)
            }
            Some(HealthStatus::Healthy | HealthStatus::Unhealthy) => self.interval_ns,
            _ => self.interval_ns,
        };
        Duration::from_nanos(ns.max(1))
    }
}

/// Image-config healthcheck as represented by Docker's OCI extension.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageHealthcheck {
    #[serde(default, rename = "Test", skip_serializing_if = "Option::is_none")]
    pub test: Option<Vec<String>>,
    #[serde(default, rename = "Interval", skip_serializing_if = "Option::is_none")]
    pub interval: Option<i64>,
    #[serde(default, rename = "Timeout", skip_serializing_if = "Option::is_none")]
    pub timeout: Option<i64>,
    #[serde(
        default,
        rename = "StartPeriod",
        skip_serializing_if = "Option::is_none"
    )]
    pub start_period: Option<i64>,
    #[serde(
        default,
        rename = "StartInterval",
        skip_serializing_if = "Option::is_none"
    )]
    pub start_interval: Option<i64>,
    #[serde(default, rename = "Retries", skip_serializing_if = "Option::is_none")]
    pub retries: Option<i64>,
}

/// Explicit `run` overrides for an image-provided healthcheck.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CliOptions {
    pub cmd: Option<String>,
    pub interval_ns: Option<u64>,
    pub timeout_ns: Option<u64>,
    pub start_period_ns: Option<u64>,
    pub start_interval_ns: Option<u64>,
    pub retries: Option<u32>,
    pub disabled: bool,
}

impl CliOptions {
    pub fn has_settings(&self) -> bool {
        self.cmd.is_some()
            || self.interval_ns.is_some()
            || self.timeout_ns.is_some()
            || self.start_period_ns.is_some()
            || self.start_interval_ns.is_some()
            || self.retries.is_some()
    }
}

/// Convert a Docker image healthcheck into Zerun's validated configuration.
pub fn from_image(raw: &ImageHealthcheck) -> Result<Option<Healthcheck>, String> {
    let Some(test) = raw.test.as_ref() else {
        return Ok(None);
    };
    if test.is_empty() {
        return Ok(None);
    }
    if test.len() == 1 && test[0] == "NONE" {
        return Ok(None);
    }
    let mut check = Healthcheck::new(test.clone())?;
    check.interval_ns = image_duration(raw.interval, DEFAULT_INTERVAL_NS, false);
    check.timeout_ns = image_duration(raw.timeout, DEFAULT_TIMEOUT_NS, false);
    check.start_period_ns = image_duration(raw.start_period, DEFAULT_START_PERIOD_NS, true);
    check.start_interval_ns = match raw.start_interval {
        Some(value) if value > 0 => Some(value as u64),
        _ => None,
    };
    check.retries = match raw.retries {
        Some(value) if value > 0 => u32::try_from(value)
            .map_err(|_| "image config Healthcheck.Retries is too large".to_string())?,
        _ => DEFAULT_RETRIES,
    };
    check.validate()?;
    Ok(Some(check))
}

fn image_duration(value: Option<i64>, default: u64, allow_zero: bool) -> u64 {
    match value {
        Some(value) if value > 0 => value as u64,
        Some(0) if allow_zero => 0,
        _ => default,
    }
}

/// Apply CLI overrides on top of an image healthcheck. CLI settings without a
/// command do not invent a probe when neither source selected one.
pub fn resolve(
    image: Option<Healthcheck>,
    cli: &CliOptions,
) -> Result<Option<Healthcheck>, String> {
    if cli.disabled {
        if cli.has_settings() {
            return Err("--no-healthcheck cannot be combined with --health-* options".to_string());
        }
        return Ok(None);
    }

    let mut check = match (image, cli.cmd.as_deref()) {
        (Some(mut check), Some(command)) => {
            check.test = vec!["CMD-SHELL".to_string(), command.to_string()];
            check
        }
        (Some(check), None) => check,
        (None, Some(command)) => {
            Healthcheck::new(vec!["CMD-SHELL".to_string(), command.to_string()])?
        }
        (None, None) => return Ok(None),
    };
    if let Some(value) = cli.interval_ns {
        check.interval_ns = if value == 0 {
            DEFAULT_INTERVAL_NS
        } else {
            value
        };
    }
    if let Some(value) = cli.timeout_ns {
        check.timeout_ns = if value == 0 {
            DEFAULT_TIMEOUT_NS
        } else {
            value
        };
    }
    if let Some(value) = cli.start_period_ns {
        check.start_period_ns = value;
    }
    if let Some(value) = cli.start_interval_ns {
        check.start_interval_ns = (value > 0).then_some(value);
    }
    if let Some(value) = cli.retries {
        check.retries = value;
    }
    check.validate()?;
    Ok(Some(check))
}

fn validate_test(test: &[String]) -> Result<(), String> {
    let Some(kind) = test.first() else {
        return Err("healthcheck command is empty".to_string());
    };
    if test.iter().any(|arg| arg.contains('\0')) {
        return Err("healthcheck command contains a NUL byte".to_string());
    }
    match kind.as_str() {
        "CMD" if test.len() >= 2 => Ok(()),
        "CMD-SHELL" if test.len() == 2 && !test[1].is_empty() => Ok(()),
        "CMD-SHELL" => Err(
            "CMD-SHELL healthcheck must contain exactly one non-empty command string".to_string(),
        ),
        "NONE" => Err("NONE is only valid as the sole image healthcheck command".to_string()),
        _ => Err(format!(
            "healthcheck command must use CMD with an argv or CMD-SHELL with one string (found {kind})"
        )),
    }
}

/// Parse Docker/Go-style positive durations into nanoseconds.
///
/// The parser intentionally avoids floating point and accepts only finite,
/// non-negative values. A bare `0` is accepted as zero; every other value must
/// include at least one unit.
pub fn parse_duration_ns(value: &str) -> Result<u64, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("duration is empty".to_string());
    }
    if value == "0" {
        return Ok(0);
    }
    let bytes = value.as_bytes();
    let mut index = 0usize;
    let mut total: u128 = 0;
    while index < bytes.len() {
        let number_start = index;
        let mut saw_digit = false;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            saw_digit = true;
            index += 1;
        }
        let mut fraction_digits = 0u32;
        let mut fraction_start = 0usize;
        if index < bytes.len() && bytes[index] == b'.' {
            index += 1;
            fraction_start = index;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            fraction_digits = (index - fraction_start) as u32;
            if fraction_digits == 0 {
                return Err(format!("invalid duration {value:?}"));
            }
            // Keep the checked arithmetic bounded even for hostile input.
            // Eighteen decimal places are far beyond nanosecond precision for
            // every accepted unit.
            if fraction_digits > 18 {
                return Err(format!(
                    "duration has more than 18 fractional digits: {value:?}"
                ));
            }
            saw_digit = true;
        }
        if !saw_digit || index == number_start {
            return Err(format!("invalid duration {value:?}"));
        }
        let whole = value[number_start..]
            .split(['.', 'n', 'u', 'µ', 'm', 's', 'h'])
            .next()
            .unwrap_or("");
        let unit_start = index;
        while index < bytes.len() && !bytes[index].is_ascii_digit() && bytes[index] != b'.' {
            index += 1;
        }
        let unit = &value[unit_start..index];
        let multiplier = match unit {
            "ns" => 1u128,
            "us" | "µs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60 * 1_000_000_000,
            "h" => 3_600 * 1_000_000_000,
            _ => return Err(format!("invalid duration unit in {value:?}")),
        };
        let whole = if whole.is_empty() {
            0u128
        } else {
            whole
                .parse::<u128>()
                .map_err(|_| format!("duration is too large: {value:?}"))?
        };
        let fraction = if fraction_digits == 0 {
            0u128
        } else {
            let digits = value[fraction_start..fraction_start + fraction_digits as usize]
                .parse::<u128>()
                .map_err(|_| format!("invalid duration {value:?}"))?;
            digits
                .checked_mul(multiplier)
                .ok_or_else(|| format!("duration is too large: {value:?}"))?
                / 10u128.pow(fraction_digits)
        };
        let component = whole
            .checked_mul(multiplier)
            .and_then(|whole| whole.checked_add(fraction))
            .ok_or_else(|| format!("duration is too large: {value:?}"))?;
        total = total
            .checked_add(component)
            .ok_or_else(|| format!("duration is too large: {value:?}"))?;
    }
    u64::try_from(total).map_err(|_| format!("duration is too large: {value:?}"))
}

/// Compute the next health state after one probe.
///
/// Failures during the start period keep the container in `starting` and do
/// not consume retries. After that, consecutive failures remain `healthy`
/// until the retry threshold is reached, then transition to `unhealthy`.
pub fn apply_probe_result(
    current: Option<&HealthState>,
    passed: bool,
    in_start_period: bool,
    retries: u32,
) -> (HealthStatus, u32) {
    if passed {
        return (HealthStatus::Healthy, 0);
    }
    if in_start_period {
        return (HealthStatus::Starting, 0);
    }
    let failing = current
        .map(|state| state.failing_streak)
        .unwrap_or(0)
        .saturating_add(1);
    let previous = current.map(|state| state.status);
    let status = if failing >= retries.max(1) || previous == Some(HealthStatus::Unhealthy) {
        HealthStatus::Unhealthy
    } else if previous == Some(HealthStatus::Healthy) {
        HealthStatus::Healthy
    } else {
        HealthStatus::Starting
    };
    (status, failing)
}

/// A live health monitor owned by one detached reaper attempt.
#[must_use = "the reaper must stop the monitor before persisting the attempt result"]
pub struct Monitor {
    pid: i32,
    start_time: Option<u64>,
}

impl Monitor {
    /// Fork a monitor for the current workload attempt when health checking is
    /// configured. The caller must have released the lifecycle operation lock
    /// before calling this function: the child intentionally closes inherited
    /// descriptors and reopens the state files it needs.
    pub fn spawn(
        store: &Store,
        id: &str,
        workload_pid: i32,
        workload_start_time: Option<u64>,
    ) -> ZResult<Option<Self>> {
        let Some(state) = ContainerState::load(store, id) else {
            return Err(crate::zerr!(
                "detached state for {id} disappeared before health monitor"
            ));
        };
        if state.healthcheck.is_none() {
            return Ok(None);
        }
        let store = store.clone();
        let id = id.to_string();
        let owner_pid = crate::syscalls::process_id();
        match crate::syscalls::fork_process()? {
            0 => {
                let code = run_monitor(&store, &id, workload_pid, workload_start_time, owner_pid);
                crate::syscalls::exit_process(code)
            }
            pid => Ok(Some(Self {
                pid,
                start_time: crate::procinfo::process_start_time(pid),
            })),
        }
    }

    /// Stop and reap the monitor. SIGTERM is enough for the resident monitor;
    /// a bounded SIGKILL fallback prevents a wedged probe from blocking the
    /// lifecycle reaper.
    pub fn stop(mut self) {
        let child_pid = self.pid;
        let pidfd = match crate::syscalls::pidfd_open_if_exists(child_pid) {
            Ok(pidfd) => pidfd,
            Err(error) => {
                eprintln!("zerun: warning: open health monitor {child_pid}: {error}");
                None
            }
        };
        // A numeric signal is safe only when the process still has the
        // recorded start time. waitpid below always uses the exact child PID;
        // never fall back to waitpid(-1), which could reap an unrelated child.
        let numeric_identity_matches = self.start_time.is_none()
            || crate::procinfo::process_start_time(child_pid) == self.start_time;
        if let Some(pidfd) = pidfd.as_ref() {
            let _ = crate::syscalls::pidfd_send_signal_if_exists(
                std::os::fd::AsRawFd::as_raw_fd(pidfd),
                libc::SIGTERM,
            );
        } else if numeric_identity_matches {
            let _ = crate::syscalls::kill_if_exists(child_pid, libc::SIGTERM);
        }

        let deadline = Instant::now() + MONITOR_STOP_TIMEOUT;
        loop {
            match crate::syscalls::wait_pid(child_pid, libc::WNOHANG) {
                Ok(Some(_)) => {
                    self.pid = -1;
                    return;
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => break,
                Err(_) if !crate::syscalls::pid_exists(child_pid) => {
                    self.pid = -1;
                    return;
                }
                Err(error) => {
                    eprintln!("zerun: warning: wait for health monitor {child_pid}: {error}");
                    self.pid = -1;
                    return;
                }
            }
        }
        if let Some(pidfd) = pidfd.as_ref() {
            let _ = crate::syscalls::pidfd_send_signal_if_exists(
                std::os::fd::AsRawFd::as_raw_fd(pidfd),
                libc::SIGKILL,
            );
        } else if numeric_identity_matches {
            let _ = crate::syscalls::kill_if_exists(child_pid, libc::SIGKILL);
        }
        let _ = crate::syscalls::wait_pid(child_pid, 0);
        self.pid = -1;
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        if self.pid > 0 {
            // Explicit stop is preferred; this is a last-resort cleanup on an
            // error path that cannot return the monitor handle to the caller.
            let _ = crate::syscalls::kill_if_exists(self.pid, libc::SIGTERM);
            let _ = crate::syscalls::wait_pid(self.pid, 0);
        }
    }
}

fn run_monitor(
    store: &Store,
    id: &str,
    workload_pid: i32,
    workload_start_time: Option<u64>,
    owner_pid: i32,
) -> i32 {
    if let Err(error) = reset_monitor_process(owner_pid) {
        eprintln!("zerun: health monitor: {error}");
        return 1;
    }
    let started = Instant::now();
    loop {
        let Some(state) = ContainerState::load(store, id) else {
            return 0;
        };
        if state.status != Status::Running
            || state.pid != Some(workload_pid)
            || state.pid_start_time != workload_start_time
        {
            return 0;
        }
        let Some(check) = state.healthcheck.as_ref() else {
            return 0;
        };
        if state.paused {
            std::thread::sleep(MONITOR_POLL_INTERVAL);
            continue;
        }
        let delay = check.delay_for(
            state.health.as_ref(),
            check.in_start_period(started.elapsed()),
        );
        std::thread::sleep(delay);

        // Reload after sleeping: stop/pause/rename may have changed the record
        // while the monitor was idle. The probe itself is also snapshotted
        // from this current state.
        let Some(state) = ContainerState::load(store, id) else {
            return 0;
        };
        if state.status != Status::Running
            || state.pid != Some(workload_pid)
            || state.pid_start_time != workload_start_time
            || state.paused
        {
            continue;
        }
        let Some(check) = state.healthcheck.as_ref() else {
            return 0;
        };
        let in_start_period = check.in_start_period(started.elapsed());
        let probe_started = state::now_rfc3339_nanos();
        let result = probe(&state, check);
        let probe_finished = state::now_rfc3339_nanos();
        let (passed, exit_code, output) = match result {
            Ok(result) => (result.code == 0, result.code, result.output),
            Err(error) => (false, 1, format!("health monitor: {error}")),
        };
        let (status, failing_streak) = apply_probe_result(
            state.health.as_ref(),
            passed,
            in_start_period,
            check.retries,
        );
        let log = HealthLog {
            start: probe_started,
            end: probe_finished,
            exit_code,
            output,
        };
        if let Err(error) = persist_probe(
            store,
            id,
            workload_pid,
            workload_start_time,
            status,
            failing_streak,
            log,
        ) {
            eprintln!("zerun: health monitor for {id}: {error}");
        }
    }
}

fn reset_monitor_process(owner_pid: i32) -> ZResult<()> {
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        crate::syscalls::reset_signal_default(signal)?;
    }
    crate::syscalls::set_parent_death_signal(libc::SIGTERM)?;
    if crate::syscalls::parent_process_id() != owner_pid {
        return Err(crate::zerr!("health monitor owner exited during startup"));
    }
    crate::syscalls::redirect_stdio_devnull()?;
    crate::syscalls::close_fds_from(3)?;
    Ok(())
}

struct ProbeResult {
    code: i32,
    output: String,
}

fn probe(state: &ContainerState, check: &Healthcheck) -> ZResult<ProbeResult> {
    let argv = check
        .command_argv()
        .map_err(|error| crate::zerr!("invalid healthcheck: {error}"))?;
    let timeout = Duration::from_nanos(check.timeout_ns.max(1));
    let result = crate::execc::run_captured(state, &argv, timeout, MAX_PROBE_OUTPUT_BYTES)?;
    Ok(ProbeResult {
        code: if result.timed_out { 124 } else { result.code },
        output: result.output,
    })
}

fn persist_probe(
    store: &Store,
    id: &str,
    workload_pid: i32,
    workload_start_time: Option<u64>,
    status: HealthStatus,
    failing_streak: u32,
    log: HealthLog,
) -> Result<(), String> {
    let _lock = state::ContainerOperationLock::acquire(store, id, Duration::from_millis(500))?;
    let Some(mut st) = ContainerState::load(store, id) else {
        return Ok(());
    };
    if st.status != Status::Running
        || st.paused
        || st.pid != Some(workload_pid)
        || st.pid_start_time != workload_start_time
        || st.healthcheck.is_none()
    {
        return Ok(());
    }
    let health = st.health.get_or_insert_with(HealthState::starting);
    health.status = status;
    health.failing_streak = failing_streak;
    health.log.push(log);
    if health.log.len() > MAX_HEALTH_LOG_ENTRIES {
        let excess = health.log.len() - MAX_HEALTH_LOG_ENTRIES;
        health.log.drain(..excess);
    }
    st.save(store).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn parses_go_durations_without_float_rounding() {
        assert_eq!(parse_duration_ns("0").unwrap(), 0);
        assert_eq!(parse_duration_ns("500ms").unwrap(), 500_000_000);
        assert_eq!(parse_duration_ns("1.5s").unwrap(), 1_500_000_000);
        assert_eq!(parse_duration_ns("1m30s").unwrap(), 90_000_000_000);
        assert_eq!(parse_duration_ns("1h2m3.5s").unwrap(), 3_723_500_000_000);
        assert_eq!(parse_duration_ns("250us").unwrap(), 250_000);
        for invalid in ["", "-1s", "1", "1d", "1.s", "1..2s", "NaN", "1s junk"] {
            assert!(
                parse_duration_ns(invalid).is_err(),
                "accepted invalid duration {invalid:?}"
            );
        }
        let excessive_precision = format!("0.{}s", "1".repeat(1000));
        assert!(parse_duration_ns(&excessive_precision).is_err());
    }

    #[test]
    fn converts_image_healthchecks_and_honors_none() {
        let check = from_image(&ImageHealthcheck {
            test: Some(vec!["CMD-SHELL".to_string(), "test -f /ok".to_string()]),
            interval: Some(5_000_000_000),
            timeout: Some(2_000_000_000),
            start_period: Some(10_000_000_000),
            start_interval: Some(1_000_000_000),
            retries: Some(4),
        })
        .unwrap()
        .unwrap();
        assert_eq!(check.interval_ns, 5_000_000_000);
        assert_eq!(check.timeout_ns, 2_000_000_000);
        assert_eq!(check.start_period_ns, 10_000_000_000);
        assert_eq!(check.start_interval_ns, Some(1_000_000_000));
        assert_eq!(check.retries, 4);
        assert_eq!(
            check.command_argv().unwrap(),
            ["/bin/sh", "-c", "test -f /ok"]
        );

        assert!(from_image(&ImageHealthcheck {
            test: Some(vec!["NONE".to_string()]),
            ..Default::default()
        })
        .unwrap()
        .is_none());

        let encoded = check.to_image().unwrap();
        assert_eq!(encoded.test.as_deref(), Some(&check.test[..]));
        assert_eq!(encoded.interval, Some(5_000_000_000));
        assert_eq!(encoded.retries, Some(4));
        assert_eq!(from_image(&encoded).unwrap(), Some(check));
    }

    #[test]
    fn cli_command_overrides_image_and_disable_rejects_other_flags() {
        let image = Healthcheck::new(vec!["CMD".to_string(), "probe".to_string()]).unwrap();
        let check = resolve(
            Some(image),
            &CliOptions {
                cmd: Some("test -f /ready".to_string()),
                interval_ns: Some(1_000_000_000),
                retries: Some(2),
                ..Default::default()
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(check.test, ["CMD-SHELL", "test -f /ready"]);
        assert_eq!(check.interval_ns, 1_000_000_000);
        assert_eq!(check.retries, 2);
        assert!(resolve(
            None,
            &CliOptions {
                disabled: true,
                cmd: Some("true".to_string()),
                ..Default::default()
            }
        )
        .is_err());
    }

    #[test]
    fn start_period_does_not_consume_retries() {
        let starting = HealthState::starting();
        assert_eq!(
            apply_probe_result(Some(&starting), false, true, 3),
            (HealthStatus::Starting, 0)
        );
        let first_failure = HealthState {
            status: HealthStatus::Starting,
            failing_streak: 1,
            log: Vec::new(),
        };
        let second_failure = HealthState {
            status: HealthStatus::Starting,
            failing_streak: 2,
            log: Vec::new(),
        };
        assert_eq!(
            apply_probe_result(Some(&starting), false, false, 3),
            (HealthStatus::Starting, 1)
        );
        assert_eq!(
            apply_probe_result(Some(&first_failure), false, false, 3),
            (HealthStatus::Starting, 2)
        );
        assert_eq!(
            apply_probe_result(Some(&second_failure), false, false, 3),
            (HealthStatus::Unhealthy, 3)
        );
        assert_eq!(
            apply_probe_result(Some(&starting), true, false, 3),
            (HealthStatus::Healthy, 0)
        );
    }

    #[test]
    fn healthy_failures_wait_for_retry_threshold() {
        let healthy = HealthState {
            status: HealthStatus::Healthy,
            failing_streak: 0,
            log: Vec::new(),
        };
        assert_eq!(
            apply_probe_result(Some(&healthy), false, false, 2),
            (HealthStatus::Healthy, 1)
        );
        let first_failure = HealthState {
            status: HealthStatus::Healthy,
            failing_streak: 1,
            log: Vec::new(),
        };
        assert_eq!(
            apply_probe_result(Some(&first_failure), false, false, 2),
            (HealthStatus::Unhealthy, 2)
        );
    }

    #[test]
    fn start_interval_applies_only_during_the_start_period() {
        let starting = HealthState::starting();
        let healthy = HealthState {
            status: HealthStatus::Healthy,
            failing_streak: 0,
            log: Vec::new(),
        };
        let mut check = Healthcheck::new(vec!["CMD".to_string(), "true".to_string()]).unwrap();
        check.interval_ns = 30_000_000_000;
        check.start_period_ns = 10_000_000_000;
        check.start_interval_ns = Some(500_000_000);

        assert!(check.in_start_period(Duration::from_secs(9)));
        assert!(!check.in_start_period(Duration::from_secs(10)));
        assert_eq!(
            check.delay_for(Some(&starting), true),
            Duration::from_millis(500)
        );
        assert_eq!(
            check.delay_for(Some(&starting), false),
            Duration::from_secs(30)
        );
        assert_eq!(
            check.delay_for(Some(&healthy), true),
            Duration::from_secs(30)
        );

        check.start_interval_ns = None;
        assert_eq!(
            check.delay_for(Some(&starting), true),
            Duration::from_secs(5)
        );

        check.start_period_ns = 0;
        assert_eq!(
            check.delay_for(Some(&starting), check.in_start_period(Duration::ZERO)),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn monitor_paths_are_derived_from_store_identity() {
        let root = std::env::temp_dir().join(format!(
            "zerun-health-path-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let store = Store::at(root.join("data"), root.join("run"));
        store.ensure_dirs().unwrap();
        assert!(ContainerState::path(&store, "0123456789ab").starts_with(store.run_root()));
        assert!(Path::new(&ContainerState::path(&store, "0123456789ab"))
            .ends_with("containers/0123456789ab/state.json"));
        let _ = std::fs::remove_dir_all(root);
    }
}
