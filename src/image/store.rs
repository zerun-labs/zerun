//! Content-addressed image storage on top of the runtime data root.
//!
//! Layout (see `image/mod.rs` for the rationale):
//!   <data>/blobs/sha256/<hex>   raw registry blobs (manifests, configs, layers)
//!   <data>/rootfs/<hex>         materialized image rootfs, keyed by config digest
//!   <data>/images.json          tag index (name/tag -> manifest digest)
//!   <data>/images.lock          cross-process lock for index mutations
//!   <data>/image-operations.lock shared image transactions / exclusive GC
//!   <data>/rootfs-locks/<hex>   active-container leases for materialized roots
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
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
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

/// Shared lease protecting a complete image-store operation from garbage
/// collection. Keep it alive across every blob/rootfs write and the index
/// update that makes those artifacts reachable.
pub struct ImageStoreLease {
    data_root: PathBuf,
    _file: File,
}

/// Shared lease for a materialized rootfs actively used by a foreground
/// container. GC skips that rootfs while continuing to reclaim unrelated
/// images.
pub struct ImageRootfsLease {
    _file: File,
}

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

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

    /// Acquire a shared lease for a complete image-store transaction. GC
    /// takes the same lock exclusively, so it cannot sweep in-progress blobs,
    /// rootfs staging directories, or data being read by an image operation.
    pub fn lock_operations(&self) -> ZResult<ImageStoreLease> {
        let path = self.data_root.join("image-operations.lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| crate::zerr!("open image operations lock {}: {e}", path.display()))?;
        file.lock_shared()
            .map_err(|e| crate::zerr!("lock image operations {}: {e}", path.display()))?;
        Ok(ImageStoreLease {
            data_root: self.data_root.clone(),
            _file: file,
        })
    }

    pub(crate) fn validate_operation_lease(&self, lease: &ImageStoreLease) -> ZResult<()> {
        if lease.data_root != self.data_root {
            return Err(crate::zerr!(
                "image-store operation lease belongs to another data root"
            ));
        }
        Ok(())
    }

    /// Keep an image rootfs alive while a container uses it without holding
    /// the global transaction lease for the entire workload lifetime. Call
    /// while holding `lock_operations()` so GC cannot race lease acquisition.
    pub fn lock_rootfs_path(
        &self,
        operation: &ImageStoreLease,
        rootfs: &Path,
    ) -> ZResult<ImageRootfsLease> {
        self.validate_operation_lease(operation)?;
        if rootfs.parent() != Some(self.rootfs_dir().as_path()) {
            return Err(crate::zerr!(
                "rootfs path is outside the image store: {}",
                rootfs.display()
            ));
        }
        let config_hex = rootfs
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| crate::zerr!("invalid image rootfs path {}", rootfs.display()))?;
        digest_hex(&format!("sha256:{config_hex}"))?;
        let lock = self.open_rootfs_lock(config_hex)?;
        lock.lock_shared()
            .map_err(|e| crate::zerr!("lock image rootfs {}: {e}", rootfs.display()))?;
        Ok(ImageRootfsLease { _file: lock })
    }

    fn open_rootfs_lock(&self, config_hex: &str) -> ZResult<File> {
        digest_hex(&format!("sha256:{config_hex}"))?;
        let lock_dir = self.data_root.join("rootfs-locks");
        fsutil::mkdir_p_mode(&lock_dir, 0o700)?;
        let path = lock_dir.join(format!("{config_hex}.lock"));
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| crate::zerr!("open image rootfs lock {}: {e}", path.display()))
    }

    fn try_lock_rootfs_for_gc(&self, config_hex: &str) -> ZResult<Option<File>> {
        let lock = self.open_rootfs_lock(config_hex)?;
        match lock.try_lock() {
            Ok(()) => Ok(Some(lock)),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(error)) => Err(crate::zerr!(
                "lock image rootfs {config_hex} for garbage collection: {error}"
            )),
        }
    }

    fn lock_operations_exclusive(&self) -> ZResult<File> {
        let path = self.data_root.join("image-operations.lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| crate::zerr!("open image operations lock {}: {e}", path.display()))?;
        file.lock()
            .map_err(|e| crate::zerr!("lock image operations {}: {e}", path.display()))?;
        Ok(file)
    }

    fn ensure_dirs(&self) -> ZResult<()> {
        // Image configs and layers may come from private registries. Keep the
        // entire image store owner-only, including trees created by older
        // versions that used the process umask alone.
        let blobs = self.data_root.join("blobs");
        fsutil::mkdir_p_mode(&self.data_root, 0o700)?;
        fsutil::mkdir_p_mode(&blobs, 0o700)?;
        fsutil::mkdir_p_mode(&blobs.join("sha256"), 0o700)?;
        fsutil::mkdir_p_mode(&self.data_root.join("rootfs"), 0o700)?;
        fsutil::mkdir_p_mode(&self.data_root.join("rootfs-locks"), 0o700)?;
        Ok(())
    }

    // Low-level content/index helpers intentionally do not nest operation
    // locks. Their multi-step callers (pull/load/commit/run/save/push) hold a
    // shared operation lease; GC holds it exclusively before taking images.lock.
    // --- blobs ------------------------------------------------------------

    pub fn blob_path(&self, digest: &str) -> ZResult<PathBuf> {
        let hex = digest_hex(digest)?;
        Ok(self.data_root.join("blobs").join("sha256").join(hex))
    }

    /// Verify an existing blob against the sha256 digest encoded by its path.
    /// Missing or non-regular entries are reported as `false`; filesystem
    /// errors other than not-found are returned to the caller.
    pub fn verify_blob(&self, digest: &str) -> ZResult<bool> {
        let expected = digest_hex(digest)?;
        let path = self.data_root.join("blobs").join("sha256").join(&expected);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(crate::zerr!("stat blob {digest}: {error}"));
            }
        };
        if !metadata.file_type().is_file() {
            return Ok(false);
        }
        Ok(sha256_file(&path)? == expected)
    }

    /// Boolean compatibility wrapper for callers that cannot propagate an
    /// integrity-check error. New storage paths should prefer [`verify_blob`].
    #[allow(dead_code)]
    pub fn has_blob(&self, digest: &str) -> bool {
        self.verify_blob(digest).unwrap_or(false)
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
        let expected = digest_hex(digest)?;
        let actual = sha256_hex(bytes);
        if actual != expected {
            return Err(crate::zerr!(
                "blob digest mismatch: expected sha256:{expected}, got sha256:{actual}"
            ));
        }
        let path = self.data_root.join("blobs").join("sha256").join(&expected);
        if self.verify_blob(digest)? {
            return Ok(());
        }

        let tmp = self.tmp_path(&format!("blob-{short}-incoming", short = &expected[..8]));
        let result = (|| -> ZResult<()> {
            let mut out = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|error| crate::zerr!("create blob temp file: {error}"))?;
            out.write_all(bytes)
                .map_err(|error| crate::zerr!("write blob {digest}: {error}"))?;
            out.sync_all()
                .map_err(|error| crate::zerr!("sync blob {digest}: {error}"))?;
            self.install_blob_temp(&tmp, &path, digest)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }

    /// Stream a blob body from `reader` into the store, hashing as it goes and
    /// verifying the digest before the file is made visible.
    pub fn store_blob_stream<R: Read>(&self, digest: &str, reader: R) -> ZResult<()> {
        let expected = digest_hex(digest)?;
        let path = self.data_root.join("blobs").join("sha256").join(&expected);
        if self.verify_blob(digest)? {
            return Ok(());
        }
        let tmp = self.tmp_path(&format!("blob-{short}-incoming", short = &expected[..8]));
        let result = (|| -> ZResult<()> {
            let mut hasher = Sha256::new();
            let mut out = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|e| crate::zerr!("create blob temp file: {e}"))?;
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
            out.sync_all()
                .map_err(|e| crate::zerr!("sync blob body: {e}"))?;
            let actual = hex(&hasher.finalize());
            if actual != expected {
                return Err(crate::zerr!(
                    "blob digest mismatch: expected sha256:{expected}, got sha256:{actual}"
                ));
            }
            self.install_blob_temp(&tmp, &path, digest)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
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
        let metadata = fs::symlink_metadata(source)
            .map_err(|e| crate::zerr!("stat blob {}: {e}", source.display()))?;
        if !metadata.file_type().is_file() {
            return Err(crate::zerr!(
                "blob source {} is not a regular file",
                source.display()
            ));
        }
        let digest = format!("sha256:{}", sha256_file(source)?);
        let path = self.blob_path(&digest)?;
        let size = metadata.len();
        if self.verify_blob(&digest)? {
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
        let _operation = self.lock_operations()?;
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
        let _operation = self.lock_operations()?;
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

    /// Best-effort byte size that garbage collection would reclaim, excluding
    /// the supplied protected rootfs paths.
    ///
    /// This stays a read-only dry run so `system df` can report stale pull
    /// artifacts without mutating the store or requiring a privileged caller.
    pub fn reclaimable_bytes_with_protected(&self, protected_rootfs: &BTreeSet<PathBuf>) -> u64 {
        let Ok(_operation) = self.lock_operations() else {
            return 0;
        };
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
                let key = format!("sha256:{name}");
                if name.starts_with(".tmp-") || !keep_blobs.contains(&key) {
                    total += fsutil::dir_size(&entry.path());
                }
            }
        }
        let rootfs_dir = self.data_root.join("rootfs");
        if let Ok(rd) = fs::read_dir(&rootfs_dir) {
            for entry in rd.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if name.starts_with(".tmp-") {
                    total += fsutil::dir_size(&entry.path());
                    continue;
                }
                if keep_rootfs.contains(name) || protected_rootfs.contains(&entry.path()) {
                    continue;
                }
                if name.len() == 64 && name.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    let Ok(Some(_rootfs_lock)) = self.try_lock_rootfs_for_gc(name) else {
                        continue;
                    };
                    total += fsutil::dir_size(&entry.path());
                } else {
                    total += fsutil::dir_size(&entry.path());
                }
            }
        }
        total
    }

    /// Delete blobs and rootfs dirs no longer reachable from the tag index.
    /// Best-effort per entry: a broken record must not wedge `rmi`.
    ///
    /// Materialized rootfs directories supplied in `protected_rootfs` are kept
    /// even when their image tag is no longer present.
    /// Recompute external rootfs protections after the GC transaction lock is
    /// held. This closes races with a detached run that persists its state
    /// while GC is waiting to start. The callback must not re-enter this image
    /// store because the exclusive operation lock is already held.
    pub fn gc_with_protected_from<F>(&self, protected_rootfs: F) -> ZResult<()>
    where
        F: FnOnce() -> BTreeSet<PathBuf>,
    {
        let _operation = self.lock_operations_exclusive()?;
        let protected_rootfs = protected_rootfs();
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
                if name.starts_with(".tmp-") || protected_rootfs.contains(&entry.path()) {
                    continue;
                }
                if name.len() == 64 && name.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    let Some(rootfs_lock) = self.try_lock_rootfs_for_gc(name)? else {
                        continue;
                    };
                    if !keep_rootfs.contains(name) {
                        fsutil::remove_dir_all_quiet(&entry.path());
                    }
                    // The global exclusive operation lock prevents new lease
                    // openers. If the per-rootfs lock is uncontended, removing
                    // this now-idle lock inode is safe and avoids permanent
                    // metadata growth for every image ever run.
                    drop(rootfs_lock);
                    let _ = fs::remove_file(
                        self.data_root
                            .join("rootfs-locks")
                            .join(format!("{name}.lock")),
                    );
                } else if !keep_rootfs.contains(name) {
                    // Legacy or malformed rootfs entries cannot be named by a
                    // valid config digest and therefore cannot have a lease.
                    fsutil::remove_dir_all_quiet(&entry.path());
                }
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

    fn install_blob_temp(&self, tmp: &Path, path: &Path, digest: &str) -> ZResult<()> {
        fs::rename(tmp, path).map_err(|error| crate::zerr!("install blob {digest}: {error}"))
    }

    fn tmp_path(&self, what: &str) -> PathBuf {
        let sequence = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        self.data_root
            .join("blobs")
            .join("sha256")
            .join(format!(".tmp-{}-{sequence}-{what}", std::process::id()))
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
        assert!(!s.verify_blob(&d).unwrap());
        s.write_blob(&d, content).unwrap();
        assert!(s.verify_blob(&d).unwrap());
        assert_eq!(s.read_blob(&d).unwrap().unwrap(), content);
        // Mismatched content is rejected (digest is checked before install).
        let bad_d = format!("sha256:{}", sha256_hex(b"other"));
        assert!(s.write_blob(&bad_d, b"different").is_err());
        let _ = fs::remove_dir_all(&s.data_root);
    }

    #[test]
    fn existing_corrupt_blob_is_not_trusted_and_is_replaced() {
        let s = test_store();
        let content = b"trusted content";
        let digest = format!("sha256:{}", sha256_hex(content));
        let path = s.blob_path(&digest).unwrap();

        s.write_blob(&digest, content).unwrap();
        fs::write(&path, b"tampered content").unwrap();
        assert!(!s.verify_blob(&digest).unwrap());

        s.write_blob(&digest, content).unwrap();
        assert!(s.verify_blob(&digest).unwrap());
        assert_eq!(s.read_blob(&digest).unwrap().unwrap(), content);

        fs::write(&path, b"truncated").unwrap();
        s.store_blob_stream(&digest, &content[..]).unwrap();
        assert!(s.verify_blob(&digest).unwrap());
        assert_eq!(s.read_blob(&digest).unwrap().unwrap(), content);

        let _ = fs::remove_dir_all(&s.data_root);
    }

    #[test]
    fn blob_writer_races_keep_a_valid_content_addressed_file() {
        let s = Arc::new(test_store());
        let content = Arc::new(b"concurrent content".to_vec());
        let digest = format!("sha256:{}", sha256_hex(&content));
        let barrier = Arc::new(Barrier::new(4));
        let mut workers = Vec::new();
        for _ in 0..4 {
            let s = Arc::clone(&s);
            let content = Arc::clone(&content);
            let barrier = Arc::clone(&barrier);
            let digest = digest.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                s.store_blob_stream(&digest, &content[..]).unwrap();
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        assert!(s.verify_blob(&digest).unwrap());
        assert_eq!(s.read_blob(&digest).unwrap().unwrap(), *content);
        let _ = fs::remove_dir_all(&s.data_root);
    }

    #[test]
    fn reclaimable_dry_run_matches_gc_scope() {
        let s = test_store();
        let kept = b"kept blob";
        let kept_digest = format!("sha256:{}", sha256_hex(kept));
        s.write_blob(&kept_digest, kept).unwrap();
        s.add_image(
            "docker.io/example/kept",
            Some("latest"),
            &kept_digest,
            &format!("sha256:{}", "0".repeat(64)),
            0,
        )
        .unwrap();

        let orphan = b"orphan blob";
        let orphan_digest = format!("sha256:{}", sha256_hex(orphan));
        s.write_blob(&orphan_digest, orphan).unwrap();
        let orphan_rootfs = s.rootfs_dir().join("orphanroot");
        std::fs::create_dir_all(&orphan_rootfs).unwrap();
        std::fs::write(orphan_rootfs.join("marker"), b"orphan rootfs").unwrap();
        let expected = orphan.len() as u64 + b"orphan rootfs".len() as u64;
        assert_eq!(
            s.reclaimable_bytes_with_protected(&BTreeSet::new()),
            expected
        );

        s.gc_with_protected_from(BTreeSet::new).unwrap();
        assert!(s.verify_blob(&kept_digest).unwrap());
        assert!(!s.verify_blob(&orphan_digest).unwrap());
        assert!(!orphan_rootfs.exists());
        assert_eq!(s.reclaimable_bytes_with_protected(&BTreeSet::new()), 0);
    }

    #[test]
    fn garbage_collection_waits_for_store_transactions() {
        let s = test_store();
        let lease = s.lock_operations().unwrap();
        let lock_path = s.data_root.join("image-operations.lock");
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(lock_path)
            .unwrap();
        assert!(matches!(
            contender.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        drop(lease);
        contender.try_lock().unwrap();
        let _ = fs::remove_dir_all(&s.data_root);
    }

    #[test]
    fn gc_recomputes_container_protections_after_acquiring_its_lock() {
        let s = test_store();
        let operation = s.lock_operations().unwrap();
        let op_lock_path = s.data_root.join("image-operations.lock");
        let gc_root = s.rootfs_dir().join("container-root");
        fs::create_dir_all(&gc_root).unwrap();
        fs::write(gc_root.join("marker"), b"keep me").unwrap();
        let data_root = s.data_root.clone();
        let gc_root_for_thread = gc_root.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let gc = std::thread::spawn(move || {
            let gc_store = ImageStore::at(&data_root).unwrap();
            started_tx.send(()).unwrap();
            gc_store
                .gc_with_protected_from(|| {
                    let probe = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&op_lock_path)
                        .unwrap();
                    assert!(matches!(
                        probe.try_lock_shared(),
                        Err(std::fs::TryLockError::WouldBlock)
                    ));
                    BTreeSet::from([gc_root_for_thread.clone()])
                })
                .unwrap();
        });
        started_rx.recv().unwrap();
        drop(operation);
        gc.join().unwrap();
        assert!(gc_root.join("marker").is_file());
        let _ = fs::remove_dir_all(&s.data_root);
    }

    #[test]
    fn garbage_collection_preserves_an_active_rootfs_lease() {
        let s = test_store();
        let config_hex = "a".repeat(64);
        let rootfs = s.rootfs_dir().join(&config_hex);
        fs::create_dir_all(&rootfs).unwrap();
        fs::write(rootfs.join("marker"), b"active rootfs").unwrap();

        // The global lease closes the lookup-to-rootfs-lease race. Once the
        // rootfs lease is held, unrelated image operations and GC can resume.
        let operation = s.lock_operations().unwrap();
        let rootfs_lease = s.lock_rootfs_path(&operation, &rootfs).unwrap();
        drop(operation);
        assert_eq!(
            s.reclaimable_bytes_with_protected(&BTreeSet::new()),
            0,
            "active rootfs leases must not be reported as reclaimable"
        );
        s.gc_with_protected_from(BTreeSet::new).unwrap();
        assert!(rootfs.join("marker").is_file());

        drop(rootfs_lease);
        s.gc_with_protected_from(BTreeSet::new).unwrap();
        assert!(!rootfs.exists());
        let _ = fs::remove_dir_all(&s.data_root);
    }

    #[test]
    fn gc_cleans_idle_rootfs_lock_files_for_retained_images() {
        let s = test_store();
        let config_hex = "b".repeat(64);
        let config_digest = format!("sha256:{config_hex}");
        let rootfs = s.rootfs_dir().join(&config_hex);
        fs::create_dir_all(&rootfs).unwrap();
        fs::write(rootfs.join("marker"), b"keep me").unwrap();
        s.add_image(
            "docker.io/example/retained",
            Some("latest"),
            &format!("sha256:{}", "c".repeat(64)),
            &config_digest,
            0,
        )
        .unwrap();
        let lock_path = s
            .data_root
            .join("rootfs-locks")
            .join(format!("{config_hex}.lock"));
        let operation = s.lock_operations().unwrap();
        drop(s.lock_rootfs_path(&operation, &rootfs).unwrap());
        drop(operation);
        assert!(lock_path.exists());

        s.gc_with_protected_from(BTreeSet::new).unwrap();
        assert!(rootfs.join("marker").is_file());
        assert!(!lock_path.exists());
        let _ = fs::remove_dir_all(&s.data_root);
    }

    #[test]
    fn gc_preserves_rootfs_referenced_by_a_container() {
        let s = test_store();
        let protected = s.rootfs_dir().join("container-root");
        let orphan = s.rootfs_dir().join("orphan-root");
        std::fs::create_dir_all(&protected).unwrap();
        std::fs::write(protected.join("marker"), b"keep me").unwrap();
        std::fs::create_dir_all(&orphan).unwrap();
        std::fs::write(orphan.join("marker"), b"remove me").unwrap();

        let protected_set = BTreeSet::from([protected.clone()]);
        assert_eq!(
            s.reclaimable_bytes_with_protected(&protected_set),
            b"remove me".len() as u64
        );
        s.gc_with_protected_from(|| protected_set.clone()).unwrap();
        assert!(protected.join("marker").is_file());
        assert!(!orphan.exists());
        let _ = fs::remove_dir_all(&s.data_root);
    }

    #[test]
    fn image_store_directories_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "zerun-image-store-mode-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        let store = ImageStore::at(&dir).unwrap();
        for path in [
            dir.clone(),
            dir.join("blobs"),
            dir.join("blobs/sha256"),
            store.rootfs_dir(),
            dir.join("rootfs-locks"),
        ] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        let operation = store.lock_operations().unwrap();
        let rootfs = store.rootfs_dir().join("d".repeat(64));
        fs::create_dir_all(&rootfs).unwrap();
        let _rootfs_lease = store.lock_rootfs_path(&operation, &rootfs).unwrap();
        for path in [
            dir.join("image-operations.lock"),
            dir.join("rootfs-locks")
                .join(format!("{}.lock", "d".repeat(64))),
        ] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        drop(operation);
        let _ = fs::remove_dir_all(&dir);
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
