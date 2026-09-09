//! Owner-only registry credential storage.
//!
//! Credentials are stored in a small JSON file in the user's config directory.
//! The secret half is base64 encoded so it does not appear as plain text in a
//! casual terminal/editor view; this is compatibility/obfuscation, not
//! encryption. File and directory permissions are the security boundary.

use crate::error::ZResult;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Username and password for one registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

impl Credential {
    /// `Basic` Authorization header value as used by OCI registries.
    pub fn authorization(&self) -> String {
        format!(
            "Basic {}",
            base64_encode(format!("{}:{}", self.username, self.password).as_bytes())
        )
    }
}

/// File-backed credential lookup and updates.
pub struct CredentialStore {
    path: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct CredentialFile {
    version: u32,
    auths: BTreeMap<String, StoredCredential>,
}

#[derive(Serialize, Deserialize)]
struct StoredCredential {
    /// base64(`<username>:<password>`), matching Docker config.json's shape.
    auth: String,
}

impl CredentialStore {
    /// Default user-level store:
    /// `$XDG_CONFIG_HOME/zerun/credentials.json` or `~/.config/zerun/...`.
    pub fn open() -> ZResult<Self> {
        let path = match std::env::var_os("ZERUN_CREDENTIALS") {
            Some(v) => PathBuf::from(v),
            None => match std::env::var_os("XDG_CONFIG_HOME") {
                Some(xdg) if !xdg.is_empty() => {
                    PathBuf::from(xdg).join("zerun").join("credentials.json")
                }
                _ => {
                    let home = std::env::var_os("HOME").ok_or_else(|| {
                        crate::zerr!("cannot locate credentials (set HOME or ZERUN_CREDENTIALS)")
                    })?;
                    PathBuf::from(home)
                        .join(".config")
                        .join("zerun")
                        .join("credentials.json")
                }
            },
        };
        Ok(Self { path })
    }

    /// Load credentials, keyed by registry hostname.
    pub fn all(&self) -> ZResult<BTreeMap<String, Credential>> {
        if !self.path.exists() {
            return Ok(BTreeMap::new());
        }
        let bytes = fs::read(&self.path)
            .map_err(|e| crate::zerr!("read registry credentials {}: {e}", self.path.display()))?;
        let file: CredentialFile = serde_json::from_slice(&bytes)
            .map_err(|e| crate::zerr!("parse registry credentials {}: {e}", self.path.display()))?;
        if file.version != 1 {
            return Err(crate::zerr!(
                "unsupported registry credential file version {}",
                file.version
            ));
        }

        let mut out = BTreeMap::new();
        for (registry, stored) in file.auths {
            let Some(decoded) = base64_decode(&stored.auth) else {
                return Err(crate::zerr!(
                    "invalid auth entry for registry '{registry}' in {}",
                    self.path.display()
                ));
            };
            let joined = String::from_utf8(decoded).map_err(|_| {
                crate::zerr!("auth entry for registry '{registry}' is not valid UTF-8")
            })?;
            let Some((username, password)) = joined.split_once(':') else {
                return Err(crate::zerr!(
                    "auth entry for registry '{registry}' has no username"
                ));
            };
            out.insert(
                registry,
                Credential {
                    username: username.to_string(),
                    password: password.to_string(),
                },
            );
        }
        Ok(out)
    }

    /// Add or replace credentials, validating and preserving other entries.
    pub fn set(&self, registry: &str, credential: &Credential) -> ZResult<()> {
        let registry = normalize_registry(registry)?;
        validate_credential(credential)?;

        let mut existing = self.all()?;
        existing.insert(registry.clone(), credential.clone());
        self.write(&existing)?;
        Ok(())
    }

    /// Remove credentials. Returns true when an entry existed.
    pub fn remove(&self, registry: &str) -> ZResult<bool> {
        let registry = normalize_registry(registry)?;
        let mut existing = self.all()?;
        let removed = existing.remove(&registry).is_some();
        if removed {
            self.write(&existing)?;
        }
        Ok(removed)
    }

    fn write(&self, credentials: &BTreeMap<String, Credential>) -> ZResult<()> {
        let mut auths = BTreeMap::new();
        for (registry, credential) in credentials {
            let joined = format!("{}:{}", credential.username, credential.password);
            auths.insert(
                registry.clone(),
                StoredCredential {
                    auth: base64_encode(joined.as_bytes()),
                },
            );
        }
        let file = CredentialFile { version: 1, auths };
        let bytes = serde_json::to_vec_pretty(&file)
            .map_err(|e| crate::zerr!("serialize registry credentials: {e}"))?;
        atomic_write_private(&self.path, &bytes)?;
        Ok(())
    }
}

/// Normalize a user-supplied registry host for both login and image lookups.
pub fn normalize_registry(input: &str) -> ZResult<String> {
    let mut value = input.trim();
    if let Some(rest) = value.strip_prefix("https://") {
        value = rest;
    } else if let Some(rest) = value.strip_prefix("http://") {
        return Err(crate::zerr!(
            "insecure HTTP registries are not supported; use https://{rest}"
        ));
    }
    let value = value.trim_end_matches('/');
    if value.is_empty() {
        return Err(crate::zerr!("registry hostname is required"));
    }
    if value
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '/' || c == '@')
    {
        return Err(crate::zerr!(
            "invalid registry hostname '{input}' (use HOST[:PORT], without a path or credentials)"
        ));
    }
    let host = value.to_lowercase();
    if matches!(host.as_str(), "index.docker.io" | "registry-1.docker.io") {
        return Ok("docker.io".to_string());
    }
    Ok(host)
}

fn validate_credential(credential: &Credential) -> ZResult<()> {
    let invalid = |s: &str| s.is_empty() || s.chars().any(char::is_control);
    if invalid(&credential.username) {
        return Err(crate::zerr!(
            "registry username is empty or contains control characters"
        ));
    }
    if invalid(&credential.password) {
        return Err(crate::zerr!(
            "registry password is empty or contains control characters"
        ));
    }
    Ok(())
}

/// Write bytes with mode 0600, replacing the destination atomically when possible.
fn atomic_write_private(path: &Path, bytes: &[u8]) -> ZResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| crate::zerr!("credential path has no parent directory"))?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .map_err(|e| crate::zerr!("create credential directory {}: {e}", parent.display()))?;
    // Do not silently weaken an existing config directory.
    let mode = fs::metadata(parent)
        .map(|m| m.permissions().mode() & 0o777)
        .map_err(|e| crate::zerr!("stat credential directory {}: {e}", parent.display()))?;
    if mode & 0o022 != 0 {
        return Err(crate::zerr!(
            "credential directory {} is group/world writable",
            parent.display()
        ));
    }

    let tmp = parent.join(format!(".tmp-{}-credentials", std::process::id()));
    let write = || -> ZResult<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| crate::zerr!("create temporary credentials file: {e}"))?;
        file.write_all(bytes)
            .map_err(|e| crate::zerr!("write temporary credentials file: {e}"))?;
        file.sync_all()
            .map_err(|e| crate::zerr!("sync temporary credentials file: {e}"))?;
        fs::rename(&tmp, path)
            .map_err(|e| crate::zerr!("install registry credentials {}: {e}", path.display()))?;
        // 0600 only applies at create time; tighten a pre-existing destination.
        let file =
            fs::File::open(path).map_err(|e| crate::zerr!("reopen registry credentials: {e}"))?;
        let mut permissions = file
            .metadata()
            .map_err(|e| crate::zerr!("stat registry credentials: {e}"))?
            .permissions();
        permissions.set_mode(0o600);
        file.set_permissions(permissions)
            .map_err(|e| crate::zerr!("chmod registry credentials: {e}"))
    };
    if let Err(e) = write() {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(BASE64[(n >> 18) as usize & 63] as char);
        out.push(BASE64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            BASE64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            BASE64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let value = |b: u8| -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some(u32::from(b - b'A')),
            b'a'..=b'z' => Some(u32::from(b - b'a' + 26)),
            b'0'..=b'9' => Some(u32::from(b - b'0' + 52)),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let bytes: Vec<_> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
        .collect();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        if chunk.len() == 1 {
            return None;
        }
        let mut n = 0u32;
        for (i, b) in chunk.iter().enumerate() {
            n |= value(*b)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zerun-auth-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir.join("credentials.json")
    }

    #[test]
    fn credential_store_roundtrip_and_permissions() {
        let path = temp_path("roundtrip");
        let store = CredentialStore { path: path.clone() };
        let credential = Credential {
            username: "alice".to_string(),
            password: "p@ss:word".to_string(),
        };
        store
            .set("https://Registry.Example:5000/", &credential)
            .unwrap();
        let loaded = store.all().unwrap();
        assert_eq!(loaded.get("registry.example:5000"), Some(&credential));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(store.remove("registry.example:5000").unwrap());
        assert!(store.all().unwrap().is_empty());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn registry_names_are_normalized_and_rejected() {
        assert_eq!(normalize_registry("GHCR.IO").unwrap(), "ghcr.io");
        assert_eq!(
            normalize_registry("https://registry.example:5000/").unwrap(),
            "registry.example:5000"
        );
        assert_eq!(
            normalize_registry("registry-1.docker.io").unwrap(),
            "docker.io"
        );
        assert!(normalize_registry("http://registry.example").is_err());
        assert!(normalize_registry("registry.example/path").is_err());
        assert!(normalize_registry("user@registry.example").is_err());
    }

    #[test]
    fn base64_roundtrip() {
        for value in ["", "a", "ab", "abc", "user:p@ss:word"] {
            let encoded = base64_encode(value.as_bytes());
            assert_eq!(base64_decode(&encoded).unwrap(), value.as_bytes());
        }
        assert_eq!(base64_encode(b"user:pass"), "dXNlcjpwYXNz");
    }
}
