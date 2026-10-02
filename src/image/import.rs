//! Import a plain rootfs tar as a local single-layer image (`zerun import`).
//!
//! `zerun export` streams a container filesystem as tar; import is its
//! inverse: the stream is sniffed for gzip/zstd framing, safely unpacked
//! through the hardened layer unpacker (path traversal, symlink, and device
//! guards apply), and then registered as a whole-rootfs single-layer image
//! through the same pipeline as `zerun commit`.

use crate::error::ZResult;
use crate::fsutil;
use crate::image::commit::{commit_image_with_lease, CommitOptions};
use crate::image::pull::open_layer_reader;
use crate::image::store::ImageStore;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

/// Metadata recorded on the imported image config.
#[derive(Debug, Clone, Default)]
pub struct ImportOptions {
    pub comment: Option<String>,
    pub author: Option<String>,
}

/// Import a rootfs tar (plain, gzip, or zstd) from `source` ("-" = stdin)
/// as a new local image tagged `target` (REPOSITORY[:TAG]).
pub fn import_image(
    store: &ImageStore,
    source: &Path,
    target: &str,
    options: ImportOptions,
) -> ZResult<crate::image::store::ImageRecord> {
    // Hold the shared store lease from before any temporary files or staging
    // directories are created through the final index update. GC takes this
    // lock exclusively and otherwise could delete these `.tmp-*` paths.
    let lease = store.lock_operations()?;

    // Spool the (possibly non-seekable) input so compression sniffing and
    // unpacking always operate on a regular file.
    let (spool, _spool_guard) = if source == Path::new("-") {
        let tmp = store.blob_tmp("import-stdin");
        fsutil::remove_dir_all_quiet(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let spool_guard = fsutil::TempFileGuard::new(tmp.clone());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| crate::zerr!("create import spool: {e}"))?;
        std::io::copy(&mut std::io::stdin().lock(), &mut file)
            .map_err(|e| crate::zerr!("read import stream from stdin: {e}"))?;
        file.flush()
            .map_err(|e| crate::zerr!("flush import spool: {e}"))?;
        drop(file);
        (tmp, Some(spool_guard))
    } else {
        if !source.exists() {
            return Err(crate::zerr!(
                "import file does not exist: {}",
                source.display()
            ));
        }
        (source.to_path_buf(), None)
    };

    // Sniff compression framing from the spooled bytes, then unpack through
    // the hardened layer unpacker into a staging rootfs.
    let staging = store.blob_tmp("import-rootfs");
    fsutil::remove_dir_all_quiet(&staging);
    let _ = std::fs::remove_file(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| crate::zerr!("create import staging: {e}"))?;
    let result = open_layer_reader(&spool, "")
        .and_then(|reader| {
            crate::image::unpack::unpack_layer(reader, &staging, "imported rootfs tar")
        })
        .and_then(|()| {
            let imported = std::fs::read_dir(&staging)
                .map(|mut rd| rd.next().is_some())
                .unwrap_or(false);
            if imported {
                Ok(())
            } else {
                Err(crate::zerr!("input is not a rootfs tar (no entries found)"))
            }
        })
        .and_then(|()| {
            commit_image_with_lease(
                store,
                &staging,
                target,
                CommitOptions {
                    comment: options.comment.or(Some("imported rootfs tar".to_string())),
                    author: options.author,
                    ..Default::default()
                },
                &lease,
            )
        });
    fsutil::remove_dir_all_quiet(&staging);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQ: AtomicUsize = AtomicUsize::new(0);

    fn write_test_tar(path: &Path, gzipped: bool) {
        use tar::Builder;
        let file = std::fs::File::create(path).unwrap();
        let mut builder: Builder<Box<dyn Write>> = if gzipped {
            Builder::new(Box::new(flate2::write::GzEncoder::new(
                file,
                flate2::Compression::default(),
            )))
        } else {
            Builder::new(Box::new(file))
        };
        builder.append_dir_all("", test_rootfs()).unwrap();
        builder.into_inner().unwrap().flush().unwrap();
    }

    fn test_rootfs() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zerun-import-src-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::write(dir.join("bin/hello"), b"world").unwrap();
        dir
    }

    #[test]
    fn imports_plain_and_gzip_tars() {
        for gzipped in [false, true] {
            let data_dir = std::env::temp_dir().join(format!(
                "zerun-import-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&data_dir);
            let store = ImageStore::at(&data_dir).unwrap();
            let tar_path = data_dir.join(format!("rootfs{}.tar", if gzipped { ".gz" } else { "" }));
            write_test_tar(&tar_path, gzipped);
            let record = import_image(
                &store,
                &tar_path,
                "example/imported:v1",
                ImportOptions::default(),
            )
            .unwrap();
            assert_eq!(record.name, "docker.io/example/imported");
            assert_eq!(record.tag.as_deref(), Some("v1"));
            let rootfs = store.rootfs_path(&record.config).unwrap();
            assert_eq!(std::fs::read(rootfs.join("bin/hello")).unwrap(), b"world");
            let _ = std::fs::remove_dir_all(&data_dir);
        }
    }

    #[test]
    fn gc_waits_for_the_operation_lease_while_an_import_spool_exists() {
        use std::fs::OpenOptions;
        use std::sync::mpsc;

        let data_dir = std::env::temp_dir().join(format!(
            "zerun-import-gc-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&data_dir);
        let store = ImageStore::at(&data_dir).unwrap();
        let spool = store.blob_tmp("import-stdin");
        std::fs::write(&spool, b"in-progress import stream").unwrap();
        let lease = store.lock_operations().unwrap();
        let (entered_gc_tx, entered_gc_rx) = mpsc::channel();
        let gc_data_dir = data_dir.clone();
        let gc = std::thread::spawn(move || {
            let gc_store = ImageStore::at(&gc_data_dir).unwrap();
            gc_store
                .gc_with_protected_from(|| {
                    entered_gc_tx.send(()).unwrap();
                    std::collections::BTreeSet::new()
                })
                .unwrap();
        });

        // The callback runs only after GC acquired its exclusive lease. It
        // must not get there while import owns the shared lease, and the
        // in-progress spool must remain available to the importer.
        assert!(entered_gc_rx
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err());
        assert!(spool.is_file());
        let probe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(data_dir.join("image-operations.lock"))
            .unwrap();
        assert!(matches!(
            probe.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));

        drop(lease);
        entered_gc_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("GC should proceed after the import lease is released");
        gc.join().unwrap();
        assert!(!spool.exists());
        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn rejects_tar_without_entries() {
        let data_dir =
            std::env::temp_dir().join(format!("zerun-import-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&data_dir);
        let store = ImageStore::at(&data_dir).unwrap();
        let tar_path = data_dir.join("empty.tar");
        let file = std::fs::File::create(&tar_path).unwrap();
        let mut builder = tar::Builder::new(file);
        builder.finish().unwrap();
        let err = import_image(&store, &tar_path, "example/x", ImportOptions::default());
        assert!(err.is_err());
        let _ = std::fs::remove_dir_all(&data_dir);
    }
}
