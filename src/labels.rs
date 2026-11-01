//! Docker-compatible container label parsing.
//!
//! Labels are persisted in detached state and image configs, so both command
//! line values and label files are validated before they reach either path.
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Keep an accidental `/dev/zero` or similarly large path from consuming
/// unbounded memory. Docker label files are small metadata inputs.
pub const MAX_LABEL_FILE_BYTES: u64 = 1024 * 1024;

/// Parse one `--label` value. Docker accepts a bare key as an empty-valued
/// label, stores only the first `=`, and rejects whitespace in the key.
pub fn parse_cli(raw: &str) -> Result<(String, String), String> {
    let (key, value) = raw.split_once('=').unwrap_or((raw, ""));
    validate_key(key).map_err(|error| format!("invalid label {raw:?}: {error}"))?;
    if value.contains('\0') {
        return Err(format!("invalid label {raw:?}: value contains NUL"));
    }
    Ok((key.to_string(), value.to_string()))
}

/// Read a line-oriented label file. Blank lines and comments are ignored;
/// Docker also ignores lines without `=` rather than treating them as host
/// environment references. Later files and explicit `--label` values override
/// earlier entries when the caller applies the returned pairs in order.
pub fn load_file(path: &Path) -> Result<Vec<(String, String)>, String> {
    let file =
        File::open(path).map_err(|error| format!("open label file {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_LABEL_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read label file {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_LABEL_FILE_BYTES {
        return Err(format!(
            "label file {} exceeds the {} byte limit",
            path.display(),
            MAX_LABEL_FILE_BYTES
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| format!("label file {} is not valid UTF-8: {error}", path.display()))?;
    parse_file(text).map_err(|error| format!("label file {}: {error}", path.display()))
}

fn parse_file(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut labels = Vec::new();
    for (index, raw_line) in text.lines().enumerate() {
        let line = raw_line.strip_prefix('\u{feff}').unwrap_or(raw_line);
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        validate_key(key).map_err(|error| format!("line {}: {error}", index + 1))?;
        if value.contains('\0') {
            return Err(format!("line {}: value contains NUL", index + 1));
        }
        labels.push((key.to_string(), value.to_string()));
    }
    Ok(labels)
}

fn validate_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("name cannot be empty".to_string());
    }
    if key.contains('\0') {
        return Err("name contains NUL".to_string());
    }
    if key.chars().any(char::is_whitespace) {
        return Err(format!("name {key:?} contains whitespace"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_labels_match_docker_value_semantics() {
        assert_eq!(
            parse_cli("a=b=c").unwrap(),
            ("a".to_string(), "b=c".to_string())
        );
        assert_eq!(
            parse_cli("present").unwrap(),
            ("present".to_string(), String::new())
        );
        for invalid in ["", "=value", "white space=value", "bad\0key=value"] {
            assert!(parse_cli(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn label_files_ignore_comments_blank_and_valueless_lines() {
        let labels = parse_file(
            "\u{feff}# comment\n\nname=web\nbare\nempty=\nrepeat=first\nrepeat=second\nvalue= keep spaces \n",
        )
        .unwrap();
        assert_eq!(
            labels,
            vec![
                ("name".to_string(), "web".to_string()),
                ("empty".to_string(), String::new()),
                ("repeat".to_string(), "first".to_string()),
                ("repeat".to_string(), "second".to_string()),
                ("value".to_string(), " keep spaces ".to_string()),
            ]
        );
    }

    #[test]
    fn label_files_reject_invalid_utf8_and_oversized_inputs() {
        let root = std::env::temp_dir().join(format!(
            "zerun-label-file-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let invalid = root.join("invalid.labels");
        std::fs::write(&invalid, [b'A', b'=', 0xff]).unwrap();
        assert!(load_file(&invalid).unwrap_err().contains("UTF-8"));

        let oversized = root.join("oversized.labels");
        std::fs::write(&oversized, vec![b'A'; MAX_LABEL_FILE_BYTES as usize + 1]).unwrap();
        assert!(load_file(&oversized).unwrap_err().contains("exceeds"));

        let _ = std::fs::remove_dir_all(root);
    }
}
