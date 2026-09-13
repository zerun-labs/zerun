//! Shared parsing for binary byte-size values used by resource and mount options.
use crate::error::ZResult;

/// Parse a binary byte size without floating-point conversion.
///
/// Accepted forms include compact binary units (`64M`, `1.5G`), optional byte
/// suffixes (`64MB`), and plain byte counts (`4096`). Fractional values are
/// truncated to whole bytes after scaling.
pub(crate) fn parse_size(s: &str) -> ZResult<u64> {
    let s = s.trim();
    let (number, multiplier) = split_size_suffix(s);
    let number = number.trim();
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    if (whole.is_empty() && fraction.is_empty())
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 38
    {
        return Err(crate::zerr!("cannot parse byte size: {s}"));
    }

    let whole = if whole.is_empty() {
        0u128
    } else {
        whole
            .parse::<u128>()
            .map_err(|_| crate::zerr!("byte size is too large: {s}"))?
    };
    let scaled_whole = whole
        .checked_mul(u128::from(multiplier))
        .ok_or_else(|| crate::zerr!("byte size is too large: {s}"))?;
    let fractional = if fraction.is_empty() {
        0u128
    } else {
        let digits = fraction
            .parse::<u128>()
            .map_err(|_| crate::zerr!("byte size is too large: {s}"))?;
        let denominator = 10u128.pow(fraction.len() as u32);
        digits
            .checked_mul(u128::from(multiplier))
            .ok_or_else(|| crate::zerr!("byte size is too large: {s}"))?
            / denominator
    };
    u64::try_from(
        scaled_whole
            .checked_add(fractional)
            .ok_or_else(|| crate::zerr!("byte size is too large: {s}"))?,
    )
    .map_err(|_| crate::zerr!("byte size is too large: {s}"))
}

fn split_size_suffix(s: &str) -> (&str, u64) {
    let s = match s.as_bytes().last().copied() {
        Some(b'b' | b'B') => &s[..s.len() - 1],
        _ => s,
    };
    match s.as_bytes().last().copied() {
        Some(b'k' | b'K') => (&s[..s.len() - 1], 1024u64),
        Some(b'm' | b'M') => (&s[..s.len() - 1], 1024u64 * 1024),
        Some(b'g' | b'G') => (&s[..s.len() - 1], 1024u64 * 1024 * 1024),
        Some(b't' | b'T') => (&s[..s.len() - 1], 1024u64 * 1024 * 1024 * 1024),
        _ => (s, 1u64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_binary_sizes_without_float_edge_cases() {
        assert_eq!(parse_size("64M").unwrap(), 64 * 1024 * 1024);
        assert_eq!(parse_size("1.5G").unwrap(), 1_610_612_736);
        assert_eq!(parse_size(".5K").unwrap(), 512);
        assert_eq!(parse_size("1MB").unwrap(), 1024 * 1024);
        assert_eq!(parse_size("1T").unwrap(), 1024 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("4096").unwrap(), 4096);
    }

    #[test]
    fn rejects_non_finite_negative_and_overflow_values() {
        for value in ["", "NaN", "inf", "-1M", "1..5M", "18446744073709551616"] {
            assert!(parse_size(value).is_err(), "accepted invalid size {value}");
        }
    }
}
