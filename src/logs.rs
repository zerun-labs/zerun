//! Console-log timestamp handling and time-range selection.
//!
//! Detached console logs are line oriented and carry a fixed-width RFC3339
//! UTC timestamp at capture time:
//!
//! `2026-01-01T00:00:00.000000000Z<TAB>message`
//!
//! Legacy logs predate this format. They are displayed unchanged, but they
//! cannot participate in `--since`/`--until` selection because there is no
//! trustworthy capture-time anchor.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default detached-console rotation budget. Rotating by default keeps a
/// chatty workload from exhausting a small VPS disk; `--log-max-size 0`
/// explicitly disables rotation.
pub const DEFAULT_MAX_SIZE: u64 = 10 * 1024 * 1024;
/// Total files retained by default, including the active `console.log`.
pub const DEFAULT_MAX_FILES: usize = 3;
/// Upper bound accepted for `--log-max-file`.
///
/// The value is user-controlled persisted state and is used to construct
/// numbered paths for `logs`; keeping it bounded prevents a malformed record
/// from turning a read-only command into an allocation / filesystem scan bomb.
pub const MAX_FILES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogOptions {
    pub max_size: u64,
    pub max_files: usize,
}

impl Default for LogOptions {
    fn default() -> Self {
        Self {
            max_size: DEFAULT_MAX_SIZE,
            max_files: DEFAULT_MAX_FILES,
        }
    }
}

/// Parse a log size (`10m`, `10mb`, `1024`) and allow `0` to disable rotation.
pub fn parse_size(value: &str) -> Result<u64, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("size cannot be empty".to_string());
    }
    let value = value
        .strip_suffix(['b', 'B'])
        .filter(|value| !value.is_empty())
        .unwrap_or(value);
    let (number, multiplier) = match value.chars().last() {
        Some('k' | 'K') => (&value[..value.len() - 1], 1024_u64),
        Some('m' | 'M') => (&value[..value.len() - 1], 1024_u64 * 1024),
        Some('g' | 'G') => (&value[..value.len() - 1], 1024_u64 * 1024 * 1024),
        _ => (value, 1_u64),
    };
    let number = number.trim();
    if number.is_empty() {
        return Err("size is missing a number".to_string());
    }
    let parsed = number
        .parse::<f64>()
        .map_err(|_| "size is not a number".to_string())?;
    if !parsed.is_finite() || parsed < 0.0 {
        return Err("size must be finite and non-negative".to_string());
    }
    let bytes = parsed * multiplier as f64;
    if bytes > u64::MAX as f64 {
        return Err("size is too large".to_string());
    }
    Ok(bytes as u64)
}

/// Parse the retained-file count accepted by `--log-max-file`.
pub fn parse_max_files(value: &str) -> Result<usize, String> {
    let count = value
        .trim()
        .parse::<usize>()
        .map_err(|_| format!("invalid value '{value}'"))?;
    if count == 0 {
        return Err("must be greater than zero".to_string());
    }
    if count > MAX_FILES {
        return Err(format!("must not exceed {MAX_FILES}"));
    }
    Ok(count)
}

/// Paths in chronological order: oldest archive first, active file last.
pub fn log_paths(active: &Path, max_files: usize) -> Vec<PathBuf> {
    let max_files = max_files.max(1);
    let mut paths = Vec::with_capacity(max_files);
    for index in (1..max_files).rev() {
        let mut name = active.as_os_str().to_os_string();
        name.push(format!(".{index}"));
        paths.push(PathBuf::from(name));
    }
    paths.push(active.to_path_buf());
    paths
}

/// Inclusive nanosecond range used by `zerun logs --since/--until`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogTimeFilter {
    since: Option<i128>,
    until: Option<i128>,
}

impl LogTimeFilter {
    /// Parse Docker-style time bounds relative to the current wall clock.
    ///
    /// Accepted forms are RFC3339 timestamps (including fractional seconds and
    /// numeric offsets), UNIX epoch seconds, and Go-style relative durations
    /// such as `10m` or `1h30m`.
    pub fn parse(since: Option<&str>, until: Option<&str>) -> Result<Self, String> {
        let now = now_nanos();
        let parse_bound = |value: &str| parse_time(value, now);
        let since = since
            .map(parse_bound)
            .transpose()
            .map_err(|_| "invalid --since time".to_string())?;
        let until = until
            .map(parse_bound)
            .transpose()
            .map_err(|_| "invalid --until time".to_string())?;
        if let (Some(since), Some(until)) = (since, until) {
            if since > until {
                return Err("--since is later than --until".to_string());
            }
        }
        Ok(Self { since, until })
    }

    /// An empty filter is a no-op and avoids copying unchanged log data.
    pub fn is_active(&self) -> bool {
        self.since.is_some() || self.until.is_some()
    }

    /// Whether the wall clock has passed a fixed `--until` boundary.
    pub fn until_reached(&self) -> bool {
        self.until.is_some_and(|until| now_nanos() >= until)
    }

    fn contains(&self, timestamp: i128) -> bool {
        self.since.is_none_or(|since| timestamp >= since)
            && self.until.is_none_or(|until| timestamp <= until)
    }
}

/// Apply an optional time filter to newline-oriented log bytes.
///
/// Only lines carrying the known capture-time prefix can be selected. This is
/// deliberate: guessing their time would make time-filtered output depend on
/// surrounding timestamped records.
pub fn filter_log_lines(data: &[u8], filter: Option<&LogTimeFilter>) -> Vec<u8> {
    let Some(filter) = filter.filter(|filter| filter.is_active()) else {
        return data.to_vec();
    };
    let mut out = Vec::with_capacity(data.len());
    let mut start = 0;
    while start < data.len() {
        let end = data[start..]
            .iter()
            .position(|&byte| byte == b'\n')
            .map(|position| start + position + 1)
            .unwrap_or(data.len());
        let line = &data[start..end];
        if log_timestamp_nanos(line).is_some_and(|timestamp| filter.contains(timestamp)) {
            out.extend_from_slice(line);
        }
        start = end;
    }
    out
}

/// Return the line content after an RFC3339 nanosecond timestamp + TAB.
pub fn timestamp_prefix(line: &[u8]) -> Option<&[u8]> {
    log_timestamp_nanos(line)?;
    Some(&line[LOG_TS_LEN + 1..])
}

/// Hide the exact known timestamp prefix while leaving legacy logs untouched.
pub fn strip_log_timestamps(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut start = 0;
    while start < data.len() {
        let end = data[start..]
            .iter()
            .position(|&byte| byte == b'\n')
            .map(|position| start + position + 1)
            .unwrap_or(data.len());
        let line = &data[start..end];
        if let Some(content) = timestamp_prefix(line) {
            out.extend_from_slice(content);
        } else {
            out.extend_from_slice(line);
        }
        start = end;
    }
    out
}

const LOG_TS_LEN: usize = 30; // 2026-01-01T00:00:00.000000000Z

fn log_timestamp_nanos(line: &[u8]) -> Option<i128> {
    if line.len() <= LOG_TS_LEN + 1
        || line[LOG_TS_LEN] != b'\t'
        || !is_utc_rfc3339(&line[..LOG_TS_LEN])
    {
        return None;
    }
    let timestamp = std::str::from_utf8(&line[..LOG_TS_LEN]).ok()?;
    epoch_nanos_from_rfc3339(timestamp).ok()
}

fn is_utc_rfc3339(b: &[u8]) -> bool {
    const SEPARATORS: [u8; 30] = *b"YYYY-MM-DDTHH:MM:SS.NNNNNNNNNZ";
    b.len() == 30
        && b.iter().zip(SEPARATORS).all(|(got, want)| match want {
            b'Y' | b'M' | b'D' | b'H' | b'S' | b'N' => got.is_ascii_digit(),
            _ => *got == want,
        })
}

fn now_nanos() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as i128)
        .unwrap_or(0)
}

fn parse_time(value: &str, now: i128) -> Result<i128, ()> {
    if let Some(relative) = parse_duration(value) {
        return Ok(now - relative);
    }
    if let Some(epoch) = parse_unix_seconds(value) {
        return Ok(epoch);
    }
    epoch_nanos_from_rfc3339(value).map_err(|_| ())
}

fn parse_unix_seconds(value: &str) -> Option<i128> {
    let (whole, fraction_nanos) = match value.split_once('.') {
        Some((whole, fraction)) => {
            if fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            let mut nanos = String::with_capacity(9);
            nanos.extend(fraction.bytes().take(9).map(char::from));
            while nanos.len() < 9 {
                nanos.push('0');
            }
            (whole, nanos.parse::<i64>().ok()? as i128)
        }
        None => (value, 0),
    };
    let seconds = whole.parse::<i128>().ok()?;
    seconds
        .checked_mul(1_000_000_000)?
        .checked_add(fraction_nanos)
}

/// Parse the subset of Go duration syntax useful for log selection.
fn parse_duration(value: &str) -> Option<i128> {
    let (negative, rest) = match value.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, value.strip_prefix('+').unwrap_or(value)),
    };
    if rest.is_empty() {
        return None;
    }
    let mut total = 0i128;
    let mut rest = rest;
    let mut saw_unit = false;
    while !rest.is_empty() {
        let digits = rest
            .find(|byte: char| !byte.is_ascii_digit() && byte != '.')
            .unwrap_or(rest.len());
        if digits == 0 {
            return None;
        }
        let (number, unit_and_rest) = rest.split_at(digits);
        let unit_len = unit_and_rest
            .find(|byte: char| byte.is_ascii_digit() || byte == '.' || byte == '-' || byte == '+')
            .unwrap_or(unit_and_rest.len());
        let (unit, next) = unit_and_rest.split_at(unit_len);
        let multiplier: i128 = match unit {
            "ns" => 1,
            "us" | "µs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            "" => return None,
            _ => return None,
        };
        let amount = duration_amount(number, multiplier)?;
        total = total.checked_add(amount)?;
        rest = next;
        saw_unit = true;
    }
    if !saw_unit || total < 0 {
        return None;
    }
    Some(if negative { -total } else { total })
}

/// Multiply a decimal duration component by its unit without float precision loss.
fn duration_amount(number: &str, multiplier: i128) -> Option<i128> {
    let (whole, fraction) = match number.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (number, ""),
    };
    if whole.is_empty() && fraction.is_empty() {
        return None;
    }
    let whole = if whole.is_empty() {
        0
    } else {
        whole.parse::<i128>().ok()?
    };
    let amount = whole.checked_mul(multiplier)?;
    if fraction.is_empty() {
        return Some(amount);
    }
    let scale = 10i128.checked_pow(fraction.len().try_into().ok()?)?;
    let fraction_value = fraction.parse::<i128>().ok()?;
    let fraction_amount = fraction_value.checked_mul(multiplier)? / scale;
    amount.checked_add(fraction_amount)
}

fn epoch_nanos_from_rfc3339(value: &str) -> Result<i128, ()> {
    let b = value.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return Err(());
    }
    let num = |range: std::ops::Range<usize>| -> Result<i64, ()> {
        std::str::from_utf8(&b[range])
            .map_err(|_| ())?
            .parse()
            .map_err(|_| ())
    };
    let year = num(0..4)?;
    let month = num(5..7)?;
    let day = num(8..10)?;
    let hour = num(11..13)?;
    let minute = num(14..16)?;
    let second = num(17..19)?;
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month as u32)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(());
    }

    let mut index = 19;
    let mut nanos = 0i128;
    if b.get(index) == Some(&b'.') {
        index += 1;
        let fraction_start = index;
        while b.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if index == fraction_start {
            return Err(());
        }
        let fraction = &b[fraction_start..index.min(fraction_start + 9)];
        let mut digits = String::with_capacity(9);
        digits.extend(fraction.iter().copied().map(char::from));
        while digits.len() < 9 {
            digits.push('0');
        }
        nanos = digits.parse::<i128>().map_err(|_| ())?;
    }

    let offset_seconds = match b.get(index) {
        Some(b'Z' | b'z') => {
            if index + 1 != b.len() {
                return Err(());
            }
            0
        }
        Some(b'+' | b'-') => {
            if index + 6 != b.len() || b[index + 3] != b':' {
                return Err(());
            }
            let offset_hour = num(index + 1..index + 3)?;
            let offset_minute = num(index + 4..index + 6)?;
            if offset_hour > 23 || offset_minute > 59 {
                return Err(());
            }
            let magnitude = offset_hour * 3600 + offset_minute * 60;
            if b[index] == b'-' {
                -magnitude
            } else {
                magnitude
            }
        }
        _ => return Err(()),
    };

    let seconds = days_from_civil(year, month as u32, day as u32) * 86_400
        + hour * 3600
        + minute * 60
        + second;
    Ok((seconds - offset_seconds) as i128 * 1_000_000_000 + nanos)
}

fn days_in_month(year: i64, month: u32) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Howard Hinnant's days_from_civil (inverse of the algorithm in state.rs).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = (u64::from(m) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + u64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &[u8] = b"2026-01-01T00:00:00.100000000Z\told\n";
    const MIDDLE: &[u8] = b"2026-01-01T00:00:01.500000000Z\tmiddle\n";
    const NEW: &[u8] = b"2026-01-01T00:00:02.900000000Z\tnew\n";
    const LEGACY: &[u8] = b"legacy\n";
    const RAW: &[u8] = b"2026-01-01T00:00:00.100000000Z\thello\nlegacy\npartial";

    fn filter(since: Option<&str>, until: Option<&str>) -> LogTimeFilter {
        LogTimeFilter::parse(since, until).unwrap()
    }

    #[test]
    fn filters_timestamped_lines_and_omits_legacy_lines() {
        let selected = filter(Some("2026-01-01T00:00:01Z"), Some("2026-01-01T00:00:02Z"));
        let mut data = Vec::new();
        data.extend_from_slice(OLD);
        data.extend_from_slice(LEGACY);
        data.extend_from_slice(MIDDLE);
        data.extend_from_slice(NEW);
        assert_eq!(filter_log_lines(&data, Some(&selected)), MIDDLE);
        assert!(!filter_log_lines(&data, None).is_empty());
    }

    #[test]
    fn time_bounds_are_inclusive() {
        let at_middle = filter(
            Some("2026-01-01T00:00:01.500000000Z"),
            Some("2026-01-01T00:00:01.500000000Z"),
        );
        assert_eq!(filter_log_lines(MIDDLE, Some(&at_middle)), MIDDLE);

        let after_middle = filter(
            Some("2026-01-01T00:00:01.500000001Z"),
            Some("2026-01-01T00:00:02Z"),
        );
        assert!(filter_log_lines(MIDDLE, Some(&after_middle)).is_empty());
    }

    #[test]
    fn parses_rfc3339_fractions_and_offsets() {
        let utc = epoch_nanos_from_rfc3339("2026-01-01T00:00:01.5Z").unwrap();
        let offset = epoch_nanos_from_rfc3339("2026-01-01T01:00:01.500+01:00").unwrap();
        assert_eq!(utc, 1_767_225_601_500_000_000);
        assert_eq!(utc, offset);
    }

    #[test]
    fn parses_go_style_durations() {
        assert_eq!(parse_duration("10m"), Some(600_000_000_000));
        assert_eq!(parse_duration("1h30m"), Some(5_400_000_000_000));
        assert_eq!(parse_duration("1.5s"), Some(1_500_000_000));
        assert_eq!(parse_duration("-2s"), Some(-2_000_000_000));
        assert_eq!(parse_duration("1d"), None);
        assert_eq!(parse_duration("1"), None);
    }

    #[test]
    fn detects_when_follow_until_boundary_has_passed() {
        assert!(filter(None, Some("2000-01-01T00:00:00Z")).until_reached());
        assert!(!filter(None, Some("3000-01-01T00:00:00Z")).until_reached());
    }

    #[test]
    fn rejects_reversed_and_invalid_ranges() {
        assert_eq!(
            LogTimeFilter::parse(Some("2026-01-01T00:00:02Z"), Some("2026-01-01T00:00:01Z")),
            Err("--since is later than --until".to_string())
        );
        assert!(LogTimeFilter::parse(Some("not-a-time"), None).is_err());
    }

    #[test]
    fn log_timestamps_are_hidden_by_default_and_shown_on_request() {
        assert_eq!(strip_log_timestamps(RAW), b"hello\nlegacy\npartial");
        assert_eq!(timestamp_prefix(RAW), Some(&b"hello\nlegacy\npartial"[..]));
        let first_line_end = RAW.iter().position(|&b| b == b'\n').unwrap() + 1;
        assert_eq!(
            timestamp_prefix(&RAW[..first_line_end]),
            Some(&b"hello\n"[..])
        );
    }

    #[test]
    fn parses_log_sizes_and_builds_rotation_order() {
        assert_eq!(parse_size("0").unwrap(), 0);
        assert_eq!(parse_size("512").unwrap(), 512);
        assert_eq!(parse_size("10m").unwrap(), 10 * 1024 * 1024);
        assert_eq!(parse_size("1.5M").unwrap(), 1_572_864);
        assert_eq!(parse_size("2gb").unwrap(), 2 * 1024 * 1024 * 1024);
        assert!(parse_size("-1").is_err());
        assert!(parse_size("nope").is_err());
        assert_eq!(parse_max_files("1").unwrap(), 1);
        assert_eq!(parse_max_files("1024").unwrap(), 1024);
        assert!(parse_max_files("0").is_err());
        assert!(parse_max_files("1025").is_err());
        assert!(parse_max_files("many").is_err());

        assert_eq!(
            log_paths(Path::new("/tmp/console.log"), 1),
            vec![PathBuf::from("/tmp/console.log")]
        );
        assert_eq!(
            log_paths(Path::new("/tmp/console.log"), 3),
            vec![
                PathBuf::from("/tmp/console.log.2"),
                PathBuf::from("/tmp/console.log.1"),
                PathBuf::from("/tmp/console.log"),
            ]
        );
    }
}
