//! Workload process helpers shared by the direct-exec and mini-init paths.
//!
//! Containers built from OCI images run with an explicit environment
//! (`config.Env` + defaults + `-e` overrides). When that environment is set, the
//! process environment is cleared and replaced; command lookup uses that
//! environment's `PATH`.
use crate::error::ZResult;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Container-conventional default PATH when an image config does not set one.
pub const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Validate an environment variable name before passing it to `Command`.
/// Empty names, `=` and NUL are rejected because they cannot represent a
/// portable `NAME=VALUE` entry and Rust cannot pass NUL through execve.
pub fn validate_env_key(key: &str) -> ZResult<()> {
    if key.is_empty() {
        return Err(crate::zerr!("environment variable name cannot be empty"));
    }
    if key.contains('=') {
        return Err(crate::zerr!("environment variable name cannot contain '='"));
    }
    if key.contains('\0') {
        return Err(crate::zerr!("environment variable name cannot contain NUL"));
    }
    Ok(())
}

/// Validate a complete `NAME=VALUE` pair.
pub fn validate_env_pair(key: &str, value: &str) -> ZResult<()> {
    validate_env_key(key)?;
    if value.contains('\0') {
        return Err(crate::zerr!("environment variable '{key}' contains NUL"));
    }
    Ok(())
}

/// Validate the CLI/state representation, which may be either `NAME=VALUE` or
/// a bare `NAME` requesting host-environment passthrough.
pub fn validate_env_spec(spec: &str) -> ZResult<()> {
    match spec.split_once('=') {
        Some((key, value)) => validate_env_pair(key, value),
        None => validate_env_key(spec),
    }
}

/// Maximum accepted size for one `--env-file`.
///
/// Environment files are small configuration inputs; refusing arbitrary files
/// avoids turning a mistyped path such as `/dev/zero` into unbounded memory use.
pub const MAX_ENV_FILE_BYTES: u64 = 1024 * 1024;

/// Read and parse a `NAME=VALUE` environment file.
///
/// The runtime deliberately does not implement shell expansion or quote
/// removal: values are passed to the container byte-for-byte after the first
/// `=`. Blank lines and lines whose first non-whitespace byte is `#` are
/// ignored. Whitespace around the variable name is ignored, while the value is
/// preserved exactly (apart from the line's trailing CR/LF).
pub fn load_env_file(path: &Path) -> Result<Vec<(String, String)>, String> {
    let file = File::open(path)
        .map_err(|error| format!("open environment file {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_ENV_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read environment file {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_ENV_FILE_BYTES {
        return Err(format!(
            "environment file {} exceeds the {} byte limit",
            path.display(),
            MAX_ENV_FILE_BYTES
        ));
    }
    let text = std::str::from_utf8(&bytes).map_err(|error| {
        format!(
            "environment file {} is not valid UTF-8: {error}",
            path.display()
        )
    })?;
    parse_env_file(text).map_err(|error| format!("environment file {}: {error}", path.display()))
}

/// Canonicalize `--env-file` inputs before they are opened or persisted.
///
/// Resolving relative paths in the invoking process is important: a detached
/// container may later be resumed from another working directory, and a
/// generated systemd unit starts with `/` as its working directory.
pub fn resolve_env_file_paths(paths: &[String]) -> Result<Vec<PathBuf>, String> {
    paths
        .iter()
        .map(|raw| {
            if raw.is_empty() {
                return Err("--env-file path cannot be empty".to_string());
            }
            std::fs::canonicalize(raw).map_err(|error| format!("--env-file {raw}: {error}"))
        })
        .collect()
}

/// Load a sequence of already-canonicalized environment files in order.
///
/// Values from later files replace earlier ones when the caller applies the
/// returned ordered pairs to an environment.
pub fn load_env_files(paths: &[PathBuf]) -> Result<Vec<(String, String)>, String> {
    let mut entries = Vec::new();
    for path in paths {
        entries.extend(load_env_file(path)?);
    }
    Ok(entries)
}

/// Parse the textual form of an environment file without performing I/O.
fn parse_env_file(text: &str) -> Result<Vec<(String, String)>, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut entries = Vec::new();
    for (index, raw_line) in text.split('\n').enumerate() {
        let line_number = index + 1;
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let line = line.trim_start_matches([' ', '\t']);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((raw_key, value)) = line.split_once('=') else {
            return Err(format!(
                "line {line_number}: expected NAME=VALUE, found {line:?}"
            ));
        };
        let key = raw_key.trim_matches([' ', '\t']);
        if key.is_empty() {
            return Err(format!(
                "line {line_number}: environment variable name is empty"
            ));
        }
        if key.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
            return Err(format!(
                "line {line_number}: environment variable name contains whitespace or control characters"
            ));
        }
        validate_env_pair(key, value).map_err(|error| format!("line {line_number}: {error}"))?;
        entries.push((key.to_string(), value.to_string()));
    }
    Ok(entries)
}

/// Look up the last value of `key` in an ordered env list.
pub fn env_value<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
    env.iter()
        .rev()
        .find_map(|(k, v)| if k == key { Some(v.as_str()) } else { None })
}

/// Configure the environment of a `Command`:
/// - `Some(pairs)`: image mode — clear the inherited environment and set the
///   explicit container environment (caller guarantees PATH/HOME/HOSTNAME).
/// - `None`: legacy `--rootfs` mode — inherit the host environment and inject
///   the container-conventional defaults.
pub fn apply_env(
    cmd: &mut std::process::Command,
    env: Option<&[(String, String)]>,
    hostname: Option<&str>,
    id: &str,
) {
    match env {
        Some(pairs) => {
            cmd.env_clear();
            for (k, v) in pairs {
                cmd.env(k, v);
            }
        }
        None => {
            cmd.env("PATH", DEFAULT_PATH)
                .env("HOME", "/root")
                .env("HOSTNAME", hostname.unwrap_or(id));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_validation_rejects_execve_invalid_entries() {
        assert!(validate_env_pair("A", "ok").is_ok());
        assert!(validate_env_spec("A").is_ok());
        assert!(validate_env_spec("A=").is_ok());
        assert!(validate_env_spec("=value").is_err());
        assert!(validate_env_spec("A=B=C").is_ok());
        assert!(validate_env_pair("A", "bad\0value").is_err());
        assert!(validate_env_key("A=B").is_err());
    }
    #[test]
    fn env_file_parser_supports_comments_crlf_and_literal_values() {
        let parsed = parse_env_file(
            "\u{feff}# comment\n\n  # indented comment\r\n NAME = value with spaces \r\nEMPTY=\nEQUALS=a=b=c\nTAB=left\tright\n",
        )
        .unwrap();
        assert_eq!(
            parsed,
            vec![
                ("NAME".to_string(), " value with spaces ".to_string()),
                ("EMPTY".to_string(), String::new()),
                ("EQUALS".to_string(), "a=b=c".to_string()),
                ("TAB".to_string(), "left\tright".to_string()),
            ]
        );
    }

    #[test]
    fn env_file_parser_rejects_malformed_entries_with_line_numbers() {
        let error = parse_env_file("A=1\nnot-an-assignment\n").unwrap_err();
        assert!(error.contains("line 2"), "{error}");
        let error = parse_env_file("A=1\n BAD KEY=value\n").unwrap_err();
        assert!(error.contains("line 2"), "{error}");
        let error = parse_env_file("A=bad\0value\n").unwrap_err();
        assert!(error.contains("line 1"), "{error}");
        assert!(parse_env_file("=value\n").is_err());
    }

    #[test]
    fn env_file_loader_rejects_oversized_and_invalid_utf8_files() {
        let root = std::env::temp_dir().join(format!(
            "zerun-env-file-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let oversized = root.join("oversized.env");
        std::fs::write(&oversized, vec![b'A'; MAX_ENV_FILE_BYTES as usize + 1]).unwrap();
        assert!(load_env_file(&oversized).unwrap_err().contains("exceeds"));

        let invalid = root.join("invalid.env");
        std::fs::write(&invalid, [b'A', b'=', 0xff]).unwrap();
        assert!(load_env_file(&invalid).unwrap_err().contains("UTF-8"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn env_file_paths_are_canonicalized_and_loaded_in_order() {
        let root = std::env::temp_dir().join(format!(
            "zerun-env-file-order-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let first = root.join("first.env");
        let second = root.join("second.env");
        std::fs::write(&first, "A=first\nB=first\n").unwrap();
        std::fs::write(&second, "B=second\nC=second\n").unwrap();

        let paths =
            resolve_env_file_paths(&[first.display().to_string(), second.display().to_string()])
                .unwrap();
        assert!(paths.iter().all(|path| path.is_absolute()));
        assert_eq!(
            load_env_files(&paths).unwrap(),
            vec![
                ("A".to_string(), "first".to_string()),
                ("B".to_string(), "first".to_string()),
                ("B".to_string(), "second".to_string()),
                ("C".to_string(), "second".to_string()),
            ]
        );
        assert!(resolve_env_file_paths(&[String::new()]).is_err());

        let _ = std::fs::remove_dir_all(root);
    }
}
