//! Docker-compatible `--cidfile` output.
//!
//! The container id is a script-facing receipt, so the file must never
//! overwrite an existing path. A guard removes the file until the runtime has
//! actually started the workload, matching Docker's behavior when argument
//! validation or startup fails.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Owns a freshly-created container-id file until startup succeeds.
#[derive(Debug)]
pub struct CidFile {
    path: PathBuf,
    keep: bool,
}

impl CidFile {
    /// Create `path` exclusively and write the full container id without a
    /// trailing newline. The descriptor is closed before the caller forks.
    pub fn create(path: &Path, id: &str) -> Result<Self, String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    format!(
                        "container ID file {} already exists; remove it or choose another path",
                        path.display()
                    )
                } else {
                    format!("create container ID file {}: {error}", path.display())
                }
            })?;
        let guard = Self {
            path: path.to_path_buf(),
            keep: false,
        };
        file.write_all(id.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("write container ID file {}: {error}", path.display()))?;
        drop(file);
        // The guard now represents only the path; no descriptor leaks into a
        // detached reaper or workload.
        Ok(guard)
    }

    /// Keep the file after this guard is dropped.
    pub fn keep(mut self) {
        self.keep = true;
    }
}

impl Drop for CidFile {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        if let Err(error) = std::fs::remove_file(&self.path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                eprintln!(
                    "zerun: warn: remove container ID file {}: {error}",
                    self.path.display()
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "zerun-cidfile-{}-{}-{name}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn creates_id_file_and_removes_it_without_success() {
        let path = temp_path("drop");
        let guard = CidFile::create(&path, "0123456789ab").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "0123456789ab");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        drop(guard);
        assert!(!path.exists());
    }

    #[test]
    fn keeps_id_file_after_success_and_never_overwrites() {
        let path = temp_path("keep");
        CidFile::create(&path, "0123456789ab").unwrap().keep();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "0123456789ab");

        let error = CidFile::create(&path, "fedcba987654").unwrap_err();
        assert!(error.contains("already exists"), "{error}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "0123456789ab");
        std::fs::remove_file(path).unwrap();
    }
}
