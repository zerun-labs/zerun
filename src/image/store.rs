//! Content-addressed image storage on top of the runtime data root.
//!
//! Layout (see `image/mod.rs` for the rationale):
//!   <data>/blobs/sha256/<hex>   raw registry blobs (manifests, configs, layers)
//!   <data>/rootfs/<hex>         materialized image rootfs, keyed by config digest
//!   <data>/images.json          tag index (name/tag -> manifest digest)
//!
//! Everything is plain files + one small JSON index: there is no daemon, and
//! `rmi` garbage-collects by recomputing what is reachable from the index.
use crate::error::ZResult;
use crate::fsutil;
use crate::image::manifest;
use crate::store::Store;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// One tagged (or digest-pinned) image in the local index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImageRecord {
    /// Canonical name: `<registry>/<repository>`, e.g. `docker.io/library/alpine`.
    pub name: String,
    /// Tag; `None` for digest-only pulls (`docker.io/library/alpine@sha256:...`).
    pub tag: Option<String>,
    /// Single-architecture manifest digest (`sha256:<hex>`).
    pub manifest: String,
    /// Image config digest (`sha256:<hex>`); also keys the materialized rootfs.
    pub config: String,
    /// Sum of the compressed layer sizes (for `ze images`).
    pub size_bytes: u64,
    pub created_at: u64,
}

pub struct ImageStore {
    data_root: PathBuf,
}

impl ImageStore {
    /// Open (and create on first use) the image store under `store`'s data root.
    pub fn open(store: &Store) -> ZResult<Self> {
        Self::at(store.data_root())
    }

    /// Build a store at an explicit root (useful for tests and callers that
    /// already own a data-root path).
    pub fn at(data_root: &Path) -> ZResult<Self> {
        let s = Self {
            data_root: data_root.to_path_buf(),
        };
        s.ensure_dirs()?;
        Ok(s)
    }

    fn ensure_dirs(&self) -> ZResult<()> {
        fsutil::mkdir_p(&self.data_root.join("blobs").join("sha256"))?;
        fsutil::mkdir_p(&self.data_root.join("rootfs"))?;
        Ok(())
    }

    // --- blobs ------------------------------------------------------------

    pub fn blob_path(&self, digest: &str) -> ZResult<PathBuf> {
        let hex = digest_hex(digest)?;
        Ok(self.data_root.join("blobs").join("sha256").join(hex))
    }

    pub fn has_blob(&self, digest: &str) -> bool {
        digest_hex(digest)
            .map(|hex| {
                self.data_root
                    .join("blobs")
                    .join("sha256")
                    .join(hex)
                    .is_file()
            })
            .unwrap_or(false)
    }

    pub fn read_blob(&self, digest: &str) -> ZResult<Option<Vec<u8>>> {
        let path = self.blob_path(digest)?;
        if !path.is_file() {
            return Ok(None);
        }
        fs::read(&path)
            .map(Some)
            .map_err(|e| crate::zerr!("read blob {digest}: {e}"))
    }

    /// Store in-memory bytes as a blob, verifying `digest` matches the content.
    pub fn write_blob(&self, digest: &str, bytes: &[u8]) -> ZResult<()> {
        let path = self.blob_path(digest)?;
        if path.is_file() {
            return Ok(()); // already present
        }
        let actual = sha256_hex(bytes);
        if digest != format!("sha256:{actual}") {
            return Err(crate::zerr!(
                "blob digest mismatch: expected {digest}, got sha256:{actual}"
            ));
        }
        let tmp = self.tmp_path("blob");
        fs::write(&tmp, bytes).map_err(|e| crate::zerr!("write blob {digest}: {e}"))?;
        fs::rename(&tmp, &path).map_err(|e| crate::zerr!("install blob {digest}: {e}"))?;
        Ok(())
    }

    /// Stream a blob body from `reader` into the store, hashing as it goes and
    /// verifying the digest before the file is made visible.
    pub fn store_blob_stream<R: Read>(&self, digest: &str, reader: R) -> ZResult<()> {
        let expected = digest_hex(digest)?;
        let path = self.data_root.join("blobs").join("sha256").join(&expected);
        if path.is_file() {
            return Ok(());
        }
        let tmp = self.data_root.join("blobs").join("sha256").join(format!(
            ".tmp-{}-{}-{}",
            std::process::id(),
            &expected[..8.min(expected.len())],
            "incoming"
        ));
        let mut hasher = Sha256::new();
        {
            let mut out =
                fs::File::create(&tmp).map_err(|e| crate::zerr!("create blob temp file: {e}"))?;
            let mut buf = [0u8; 64 * 1024];
            let mut reader = reader;
            loop {
                let n = reader
                    .read(&mut buf)
                    .map_err(|e| crate::zerr!("read blob body: {e}"))?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                out.write_all(&buf[..n])
                    .map_err(|e| crate::zerr!("write blob body: {e}"))?;
            }
        }
        let actual = hex(&hasher.finalize());
        if actual != expected {
            let _ = fs::remove_file(&tmp);
            return Err(crate::zerr!(
                "blob digest mismatch: expected sha256:{expected}, got sha256:{actual}"
            ));
        }
        fs::rename(&tmp, &path).map_err(|e| crate::zerr!("install blob {digest}: {e}"))?;
        Ok(())
    }

    /// A temporary file next to blob storage; renaming it into place is
    /// atomic on the same filesystem.
    pub fn blob_tmp(&self, what: &str) -> PathBuf {
        self.tmp_path(what)
    }

    /// Hash a completed temporary file, install it as a content-addressed
    /// blob, and return its digest and size. The source must be on the image
    /// store filesystem so installation is a rename.
    pub fn install_blob_file(&self, source: &Path) -> ZResult<(String, u64)> {
        let digest = format!("sha256:{}", sha256_file(source)?);
        let path = self.blob_path(&digest)?;
        let size = fs::metadata(source)
            .map(|m| m.len())
            .map_err(|e| crate::zerr!("stat blob {}: {e}", source.display()))?;
        if path.is_file() {
            let _ = fs::remove_file(source);
            return Ok((digest, size));
        }
        fs::rename(source, &path).map_err(|e| crate::zerr!("install blob {digest}: {e}"))?;
        Ok((digest, size))
    }

    // --- materialized rootfs ------------------------------------------------

    /// Directory holding all materialized rootfs dirs (`<data>/rootfs`).
    pub fn rootfs_dir(&self) -> PathBuf {
        self.data_root.join("rootfs")
    }

    /// Rootfs directory for a config digest (`<data>/rootfs/<hex>`).
    pub fn rootfs_path(&self, config_digest: &str) -> ZResult<PathBuf> {
        Ok(self
            .data_root
            .join("rootfs")
            .join(digest_hex(config_digest)?))
    }

    /// A fresh temporary directory (same filesystem as the final rootfs) for
    /// crash-safe materialization: layers unpack here, then it is renamed.
    pub fn rootfs_tmp(&self, config_digest: &str) -> ZResult<PathBuf> {
        let hex = digest_hex(config_digest)?;
        Ok(self.data_root.join("rootfs").join(format!(
            ".tmp-{}-{}",
            std::process::id(),
            &hex[..8.min(hex.len())]
        )))
    }

    // --- tag index -----------------------------------------------------------

    fn index_path(&self) -> PathBuf {
        self.data_root.join("images.json")
    }

    pub fn records(&self) -> ZResult<Vec<ImageRecord>> {
        let path = self.index_path();
        if !path.is_file() {
            return Ok(Vec::new());
        }
        let bytes = fs::read(&path).map_err(|e| crate::zerr!("read image index: {e}"))?;
        serde_json::from_slice(&bytes).map_err(|e| crate::zerr!("parse image index: {e}"))
    }

    fn save_records(&self, records: &[ImageRecord]) -> ZResult<()> {
        let json = serde_json::to_string_pretty(records)
            .map_err(|e| crate::zerr!("serialize image index: {e}"))?;
        fsutil::atomic_write(&self.index_path(), json.as_bytes())
    }

    /// Record a newly pulled image under `name`/`tag`.
    pub fn add_image(
        &self,
        name: &str,
        tag: Option<&str>,
        manifest_digest: &str,
        config_digest: &str,
        size_bytes: u64,
    ) -> ZResult<()> {
        let mut records = self.records()?;
        // Replace a previous entry for the same name+tag (re-pull updates it).
        records.retain(|r| !(r.name == name && r.tag.as_deref() == tag));
        records.push(ImageRecord {
            name: name.to_string(),
            tag: tag.map(str::to_string),
            manifest: manifest_digest.to_string(),
            config: config_digest.to_string(),
            size_bytes,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        });
        self.save_records(&records)
    }

    /// Find the best local record for a reference: name+tag, name+`latest`, or
    /// any record whose manifest digest matches a digest-pinned reference.
    pub fn find_record(
        &self,
        name: &str,
        tag: Option<&str>,
        digest: Option<&str>,
    ) -> ZResult<Option<ImageRecord>> {
        let records = self.records()?;
        if let Some(d) = digest {
            if let Some(r) = records.iter().find(|r| r.manifest == d) {
                return Ok(Some(r.clone()));
            }
            return Ok(None);
        }
        let tag = tag.unwrap_or("latest");
        Ok(records
            .into_iter()
            .find(|r| r.name == name && r.tag.as_deref() == Some(tag)))
    }

    /// Remove one record for a reference (tag semantics like `docker rmi`).
    pub fn remove_record(
        &self,
        name: &str,
        tag: Option<&str>,
        digest: Option<&str>,
    ) -> ZResult<Option<ImageRecord>> {
        let mut records = self.records()?;
        let idx = if let Some(d) = digest {
            records.iter().position(|r| r.manifest == d)
        } else {
            let tag = tag.unwrap_or("latest");
            records
                .iter()
                .position(|r| r.name == name && r.tag.as_deref() == Some(tag))
        };
        let Some(idx) = idx else {
            return Ok(None);
        };
        let rec = records.remove(idx);
        self.save_records(&records)?;
        Ok(Some(rec))
    }

    /// Delete blobs and rootfs dirs no longer reachable from the tag index.
    /// Best-effort per entry: a broken record must not wedge `rmi`.
    pub fn gc(&self) -> ZResult<()> {
        let records = self.records()?;
        let mut keep_blobs: BTreeSet<String> = BTreeSet::new(); // "sha256:<hex>"
        let mut keep_rootfs: BTreeSet<String> = BTreeSet::new(); // "<hex>"
        for rec in &records {
            keep_blobs.insert(rec.manifest.clone());
            keep_blobs.insert(rec.config.clone());
            if let Ok(hex) = digest_hex(&rec.config) {
                keep_rootfs.insert(hex);
            }
            // Layers are reachable through the manifest.
            if let Ok(Some(bytes)) = self.read_blob(&rec.manifest) {
                if let Ok(manifest::ImageDoc::Manifest(m)) = manifest::classify(&bytes) {
                    for layer in &m.layers {
                        keep_blobs.insert(layer.digest.clone());
                    }
                }
            }
        }

        // Blob sweep.
        let blobs_dir = self.data_root.join("blobs").join("sha256");
        if let Ok(rd) = fs::read_dir(&blobs_dir) {
            for entry in rd.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if name.starts_with(".tmp-") {
                    let _ = fs::remove_file(entry.path());
                    continue;
                }
                let key = format!("sha256:{name}");
                if !keep_blobs.contains(&key) {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }

        // Rootfs sweep.
        let rootfs_dir = self.data_root.join("rootfs");
        if let Ok(rd) = fs::read_dir(&rootfs_dir) {
            for entry in rd.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if name.starts_with(".tmp-") || keep_rootfs.contains(name) {
                    continue;
                }
                fsutil::remove_dir_all_quiet(&entry.path());
            }
        }
        Ok(())
    }

    fn tmp_path(&self, what: &str) -> PathBuf {
        self.data_root
            .join("blobs")
            .join("sha256")
            .join(format!(".tmp-{}-{what}", std::process::id()))
    }
}

/// Extract the hex half of `sha256:<hex>`, validating the shape.
pub fn digest_hex(digest: &str) -> ZResult<String> {
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| crate::zerr!("unsupported digest algorithm in '{digest}'"))?;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(crate::zerr!("malformed sha256 digest '{digest}'"));
    }
    Ok(hex.to_string())
}

pub fn sha256_file(path: &Path) -> ZResult<String> {
    let mut file =
        fs::File::open(path).map_err(|e| crate::zerr!("open blob {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| crate::zerr!("read blob {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    /// Unique per-call store dir: tests run in parallel within one process, so a
    /// pid-suffixed path would be shared and races would corrupt each other.
    fn test_store() -> ImageStore {
        let dir = std::env::temp_dir().join(format!(
            "zerun-imgstore-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        ImageStore::at(&dir).unwrap()
    }

    #[test]
    fn blob_roundtrip_and_verify() {
        let s = test_store();
        let content = b"hello blob";
        let d = format!("sha256:{}", sha256_hex(content));
        assert!(!s.has_blob(&d));
        s.write_blob(&d, content).unwrap();
        assert!(s.has_blob(&d));
        assert_eq!(s.read_blob(&d).unwrap().unwrap(), content);
        // Mismatched content is rejected (digest is checked before install).
        let bad_d = format!("sha256:{}", sha256_hex(b"other"));
        assert!(s.write_blob(&bad_d, b"different").is_err());
        let _ = fs::remove_dir_all(&s.data_root);
    }

    #[test]
    fn digest_helpers() {
        assert_eq!(
            digest_hex("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert!(digest_hex("md5:abc").is_err());
        assert!(digest_hex("sha256:short").is_err());
    }

    #[test]
    fn record_add_find_remove() {
        let s = test_store();
        let m = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let c = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        s.add_image("docker.io/library/alpine", Some("latest"), m, c, 42)
            .unwrap();
        let rec = s
            .find_record("docker.io/library/alpine", None, None)
            .unwrap()
            .unwrap();
        assert_eq!(rec.tag.as_deref(), Some("latest"));
        assert_eq!(rec.manifest, m);
        // Re-pull replaces.
        s.add_image("docker.io/library/alpine", Some("latest"), m, c, 43)
            .unwrap();
        assert_eq!(s.records().unwrap().len(), 1);
        assert_eq!(s.records().unwrap()[0].size_bytes, 43);
        // Digest lookup.
        assert!(s
            .find_record("docker.io/library/alpine", None, Some(m))
            .unwrap()
            .is_some());
        let removed = s
            .remove_record("docker.io/library/alpine", None, None)
            .unwrap();
        assert!(removed.is_some());
        assert!(s.records().unwrap().is_empty());
        let _ = fs::remove_dir_all(&s.data_root);
    }
}
