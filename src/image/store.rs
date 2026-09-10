//! Content-addressed image storage on top of the runtime data root.
//!
//! Layout (see `image/mod.rs` for the rationale):
//!   <data>/blobs/sha256/<hex>   raw registry blobs (manifests, configs, layers)
//!   <data>/rootfs/<hex>         materialized image rootfs, keyed by config digest
//!   <data>/images.json          tag index (name/tag -> manifest digest)
//!   <data>/images.lock          cross-process lock for index mutations
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
use std::fs::{self, File, OpenOptions};
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
    /// Selected host-platform manifest digest (`sha256:<hex>`). For records
    /// imported from a multi-architecture archive this is the child used to
    /// run the image locally; `index` preserves the full multi-arch root.
    pub manifest: String,
    /// Optional multi-architecture index digest (`sha256:<hex>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<String>,
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

    /// Serialize image-index read-modify-write sections across CLI processes.
    /// The lock file is separate from the atomically replaced JSON so locking
    /// is stable even when the index does not exist yet.
    fn lock_index(&self) -> ZResult<File> {
        let path = self.data_root.join("images.lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| crate::zerr!("open image index lock {}: {e}", path.display()))?;
        file.lock()
            .map_err(|e| crate::zerr!("lock image index {}: {e}", path.display()))?;
        Ok(file)
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
        self.add_index_image(name, tag, manifest_digest, config_digest, size_bytes, None)
    }

    /// Record an image and optionally preserve the multi-architecture index it
    /// was selected from. This keeps `run` semantics unchanged (the selected
    /// manifest remains in `manifest`) while making the complete index pushable.
    pub fn add_index_image(
        &self,
        name: &str,
        tag: Option<&str>,
        manifest_digest: &str,
        config_digest: &str,
        size_bytes: u64,
        index_digest: Option<&str>,
    ) -> ZResult<()> {
        let _lock = self.lock_index()?;
        let mut records = self.records()?;
        let record = new_record(
            name,
            tag,
            manifest_digest,
            config_digest,
            size_bytes,
            index_digest,
        );
        upsert_record(&mut records, record);
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
        Ok(find_record_in(&records, name, tag, digest).cloned())
    }

    /// Add another tag for an existing record (Docker `tag` semantics).
    ///
    /// The target replaces any prior record with the same name/tag. The source
    /// may be tagged or digest-pinned; digest sources are useful for tagging
    /// images that were pulled without a local tag.
    pub fn tag_record(
        &self,
        source_name: &str,
        source_tag: Option<&str>,
        source_digest: Option<&str>,
        target_name: &str,
        target_tag: Option<&str>,
    ) -> ZResult<ImageRecord> {
        let _lock = self.lock_index()?;
        let mut records = self.records()?;
        let Some(source) = find_record_in(&records, source_name, source_tag, source_digest) else {
            let reference = match source_digest {
                Some(d) => format!("{source_name}@{d}"),
                None => format!("{}:{}", source_name, source_tag.unwrap_or("latest")),
            };
            return Err(crate::zerr!("No such image: {reference}"));
        };
        let Some(tag) = target_tag else {
            return Err(crate::zerr!(
                "tag target must be REPOSITORY[:TAG], not a digest reference"
            ));
        };
        let record = new_record(
            target_name,
            Some(tag),
            &source.manifest,
            &source.config,
            source.size_bytes,
            source.index.as_deref(),
        );
        upsert_record(&mut records, record.clone());
        self.save_records(&records)?;
        Ok(record)
    }

    /// Remove one record for a reference (tag semantics like `docker rmi`).
    pub fn remove_record(
        &self,
        name: &str,
        tag: Option<&str>,
        digest: Option<&str>,
    ) -> ZResult<Option<ImageRecord>> {
        let _lock = self.lock_index()?;
        let mut records = self.records()?;
        let idx = if let Some(d) = digest {
            records
                .iter()
                .position(|r| r.manifest == d || r.index.as_deref() == Some(d))
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

    /// Best-effort byte size that `gc()` would reclaim.
    ///
    /// This stays a read-only dry run so `system df` can report stale pull
    /// artifacts without mutating the store or requiring a privileged caller.
    pub fn reclaimable_bytes(&self) -> u64 {
        let Ok(_lock) = self.lock_index() else {
            return 0;
        };
        let Ok(records) = self.records() else {
            return 0;
        };
        let mut keep_blobs = BTreeSet::new();
        let mut keep_rootfs = BTreeSet::new();
        for rec in &records {
            keep_blobs.insert(rec.manifest.clone());
            if let Some(index) = &rec.index {
                keep_blobs.insert(index.clone());
            }
            keep_blobs.insert(rec.config.clone());
            if let Ok(hex) = digest_hex(&rec.config) {
                keep_rootfs.insert(hex);
            }
            if let Some(index) = &rec.index {
                self.keep_manifest_tree(index, &mut keep_blobs);
            }
            self.keep_manifest_tree(&rec.manifest, &mut keep_blobs);
        }

        let mut total = 0;
        let blobs_dir = self.data_root.join("blobs").join("sha256");
        if let Ok(rd) = fs::read_dir(&blobs_dir) {
            for entry in rd.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if name.starts_with(".tmp-") || !keep_blobs.contains(name) {
                    total += fsutil::dir_size(&entry.path());
                }
            }
        }
        let rootfs_dir = self.data_root.join("rootfs");
        if let Ok(rd) = fs::read_dir(&rootfs_dir) {
            for entry in rd.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if name.starts_with(".tmp-") || !keep_rootfs.contains(name) {
                    total += fsutil::dir_size(&entry.path());
                }
            }
        }
        total
    }

    /// Delete blobs and rootfs dirs no longer reachable from the tag index.
    /// Best-effort per entry: a broken record must not wedge `rmi`.
    pub fn gc(&self) -> ZResult<()> {
        let _lock = self.lock_index()?;
        let records = self.records()?;
        let mut keep_blobs: BTreeSet<String> = BTreeSet::new(); // "sha256:<hex>"
        let mut keep_rootfs: BTreeSet<String> = BTreeSet::new(); // "<hex>"
        for rec in &records {
            keep_blobs.insert(rec.manifest.clone());
            if let Some(index) = &rec.index {
                keep_blobs.insert(index.clone());
            }
            keep_blobs.insert(rec.config.clone());
            if let Ok(hex) = digest_hex(&rec.config) {
                keep_rootfs.insert(hex);
            }
            // Manifests, configs, and layers are reachable through the record.
            // An index is traversed recursively so every platform child and its
            // blobs survive garbage collection.
            if let Some(index) = &rec.index {
                self.keep_manifest_tree(index, &mut keep_blobs);
            }
            self.keep_manifest_tree(&rec.manifest, &mut keep_blobs);
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

    /// Mark all blobs reachable from a manifest/index as retained. Invalid or
    /// missing subtrees are ignored here so `gc` remains best-effort for broken
    /// records and can still clean everything else.
    fn keep_manifest_tree(&self, digest: &str, keep_blobs: &mut BTreeSet<String>) {
        if !keep_blobs.insert(digest.to_string()) {
            return;
        }
        let bytes = self.read_blob(digest).ok().flatten();
        let Some(bytes) = bytes else {
            return;
        };
        match manifest::classify(&bytes) {
            Ok(manifest::ImageDoc::Manifest(m)) => {
                keep_blobs.insert(m.config.digest.clone());
                for layer in &m.layers {
                    keep_blobs.insert(layer.digest.clone());
                }
            }
            Ok(manifest::ImageDoc::Index(index)) => {
                for child in &index.manifests {
                    self.keep_manifest_tree(&child.digest, keep_blobs);
                }
            }
            Err(_) => {}
        }
    }

    fn tmp_path(&self, what: &str) -> PathBuf {
        self.data_root
            .join("blobs")
            .join("sha256")
            .join(format!(".tmp-{}-{what}", std::process::id()))
    }
}

fn find_record_in<'a>(
    records: &'a [ImageRecord],
    name: &str,
    tag: Option<&str>,
    digest: Option<&str>,
) -> Option<&'a ImageRecord> {
    if let Some(digest) = digest {
        return records
            .iter()
            .find(|r| r.manifest == digest || r.index.as_deref() == Some(digest));
    }
    let tag = tag.unwrap_or("latest");
    records
        .iter()
        .find(|r| r.name == name && r.tag.as_deref() == Some(tag))
}

fn new_record(
    name: &str,
    tag: Option<&str>,
    manifest_digest: &str,
    config_digest: &str,
    size_bytes: u64,
    index_digest: Option<&str>,
) -> ImageRecord {
    ImageRecord {
        name: name.to_string(),
        tag: tag.map(str::to_string),
        manifest: manifest_digest.to_string(),
        index: index_digest.map(str::to_string),
        config: config_digest.to_string(),
        size_bytes,
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    }
}

fn upsert_record(records: &mut Vec<ImageRecord>, record: ImageRecord) {
    // Replace a previous entry for the same name+tag (re-pull/tag updates it).
    records.retain(|r| !(r.name == record.name && r.tag == record.tag));
    records.push(record);
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
    use std::sync::{Arc, Barrier};

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
    fn reclaimable_dry_run_matches_gc_scope() {
        let s = test_store();
        let orphan = b"orphan blob";
        let orphan_digest = format!("sha256:{}", sha256_hex(orphan));
        s.write_blob(&orphan_digest, orphan).unwrap();
        let orphan_rootfs = s.rootfs_dir().join("orphanroot");
        std::fs::create_dir_all(&orphan_rootfs).unwrap();
        std::fs::write(orphan_rootfs.join("marker"), b"orphan rootfs").unwrap();
        let expected = orphan.len() as u64 + b"orphan rootfs".len() as u64;
        assert_eq!(s.reclaimable_bytes(), expected);

        s.gc().unwrap();
        assert!(!s.has_blob(&orphan_digest));
        assert!(!orphan_rootfs.exists());
        assert_eq!(s.reclaimable_bytes(), 0);
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
    fn tag_record_retags_tagged_and_digest_sources() {
        let s = test_store();
        let manifest = "sha256:".to_string() + &"1".repeat(64);
        let config = "sha256:".to_string() + &"2".repeat(64);
        s.add_image(
            "docker.io/library/alpine",
            Some("3.20"),
            &manifest,
            &config,
            123,
        )
        .unwrap();
        let target = s
            .tag_record(
                "docker.io/library/alpine",
                Some("3.20"),
                None,
                "ghcr.io/org/app",
                Some("v1"),
            )
            .unwrap();
        assert_eq!(target.manifest, manifest);
        assert_eq!(target.config, config);
        assert_eq!(target.size_bytes, 123);
        assert!(s
            .find_record("ghcr.io/org/app", Some("v1"), None)
            .unwrap()
            .is_some());

        let retarget = s
            .tag_record(
                "ghcr.io/org/app",
                Some("v1"),
                None,
                "ghcr.io/org/app",
                Some("v2"),
            )
            .unwrap();
        assert_eq!(retarget.manifest, manifest);
        assert!(s
            .find_record("ghcr.io/org/app", Some("v2"), None)
            .unwrap()
            .is_some());

        let digest_source = s
            .tag_record(
                "docker.io/library/alpine",
                None,
                Some(&manifest),
                "localhost:5000/app",
                Some("latest"),
            )
            .unwrap();
        assert_eq!(digest_source.manifest, manifest);
        assert!(s
            .find_record("localhost:5000/app", Some("latest"), None)
            .unwrap()
            .is_some());
    }

    #[test]
    fn tag_record_rejects_missing_sources() {
        let s = test_store();
        let err = s
            .tag_record(
                "docker.io/library/missing",
                None,
                None,
                "localhost:5000/app",
                Some("v1"),
            )
            .unwrap_err();
        assert!(err.to_string().contains("No such image"));
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

    #[test]
    fn concurrent_record_adds_do_not_lose_tags() {
        let store = Arc::new(test_store());
        let workers = 16;
        let barrier = Arc::new(Barrier::new(workers));
        let mut handles = Vec::new();
        for i in 0..workers {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let digest = format!("sha256:{i:064x}");
                let name = format!("registry.test/app{i}");
                barrier.wait();
                store
                    .add_image(&name, Some("latest"), &digest, &digest, i as u64)
                    .unwrap();
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(store.records().unwrap().len(), workers);
        let _ = fs::remove_dir_all(&store.data_root);
    }
}
