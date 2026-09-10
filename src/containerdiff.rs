//! Container filesystem diffs against the image's materialized lower root.
//!
//! Detached containers keep their OverlayFS `upper` directory, and live
//! containers expose the same writable layer to the host. Rather than walking
//! the mounted root (which contains mounts and merged results), inspect
//! OverlayFS semantics directly: upper entries are additions/changes and
//! zero-device character files are whiteouts.
use crate::error::ZResult;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const WHITEOUT_PREFIX: &str = ".wh.";
const OPAQUE_WHITEOUT: &str = ".wh..wh..opq";

/// Docker-style change classification for `zerun diff`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Changed,
    Deleted,
}

impl ChangeKind {
    pub fn label(self) -> char {
        match self {
            Self::Added => 'A',
            Self::Changed => 'C',
            Self::Deleted => 'D',
        }
    }
}

/// One changed path, always rendered with a leading `/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub kind: ChangeKind,
    pub path: PathBuf,
}

/// Compare an OverlayFS upper layer with its materialized lower root.
///
/// The returned changes are sorted by absolute path for deterministic CLI and
/// test output. A whiteout is authoritative even if its lower victim has
/// already disappeared unexpectedly; deleted descendants of a hidden
/// directory are represented by the immediate lower child, as Docker does.
pub fn diff_roots(lower: &Path, upper: &Path) -> ZResult<Vec<Change>> {
    if !lower.is_dir() {
        return Err(crate::zerr!(
            "lower rootfs is not a directory: {}",
            lower.display()
        ));
    }
    if !upper.is_dir() {
        return Err(crate::zerr!(
            "overlay upper is not a directory: {}",
            upper.display()
        ));
    }

    let mut changes: BTreeMap<PathBuf, ChangeKind> = BTreeMap::new();
    let mut stack = vec![(upper.to_path_buf(), lower.to_path_buf(), PathBuf::new())];
    while let Some((upper_dir, lower_dir, rel)) = stack.pop() {
        let entries = read_entries(&upper_dir)?;
        let upper_names: BTreeSet<String> =
            entries.iter().map(|entry| entry.name.clone()).collect();

        if entries.iter().any(|entry| entry.name == OPAQUE_WHITEOUT) {
            for (name, _) in read_lower_entries(&lower_dir)? {
                if upper_names.contains(&name) {
                    continue; // a later upper entry overrides the opaque deletion
                }
                let path = absolute_path(&rel.join(name));
                changes.insert(path, ChangeKind::Deleted);
            }
        }

        for entry in entries {
            let Entry {
                name,
                file_type: entry_type,
                rdev,
            } = entry;
            if name == OPAQUE_WHITEOUT {
                continue;
            }
            let child_rel = rel.join(&name);
            let upper_path = upper_dir.join(&name);
            let lower_path = lower_dir.join(&name);

            if is_whiteout(&name, entry_type, rdev) {
                let victim = name
                    .strip_prefix(WHITEOUT_PREFIX)
                    .unwrap_or(&name)
                    .to_string();
                if !victim.is_empty() && fs::symlink_metadata(lower_dir.join(&victim)).is_ok() {
                    changes.insert(absolute_path(&rel.join(&victim)), ChangeKind::Deleted);
                }
                continue;
            }

            let existed = fs::symlink_metadata(&lower_path).is_ok();
            let kind = if existed {
                ChangeKind::Changed
            } else {
                ChangeKind::Added
            };
            changes.insert(absolute_path(&child_rel), kind);

            if entry_type.is_dir() {
                stack.push((upper_path, lower_path, child_rel));
            }
        }
    }

    Ok(changes
        .into_iter()
        .map(|(path, kind)| Change { kind, path })
        .collect())
}

/// A stable representation of one upper directory entry.
struct Entry {
    name: String,
    file_type: fs::FileType,
    /// Device number, captured for character devices only.
    rdev: Option<u64>,
}

/// Recognize both forms Zerun may encounter:
/// - live OverlayFS whiteouts are character devices named after their victim;
/// - OCI-style whiteout markers are character devices named `.wh.<victim>`.
fn is_whiteout(name: &str, file_type: fs::FileType, rdev: Option<u64>) -> bool {
    file_type.is_char_device() && (name.starts_with(WHITEOUT_PREFIX) || rdev == Some(0))
}

/// Return upper directory entries with enough metadata to classify whiteouts.
fn read_entries(dir: &Path) -> ZResult<Vec<Entry>> {
    let rd = fs::read_dir(dir).map_err(|e| crate::zerr!("read {}: {e}", dir.display()))?;
    let mut entries = Vec::new();
    for entry in rd {
        let entry = entry.map_err(|e| crate::zerr!("read entry in {}: {e}", dir.display()))?;
        let file_type = entry
            .file_type()
            .map_err(|e| crate::zerr!("file_type in {}: {e}", dir.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let rdev = if file_type.is_char_device() {
            fs::symlink_metadata(entry.path()).ok().map(|m| m.rdev())
        } else {
            None
        };
        entries.push(Entry {
            name,
            file_type,
            rdev,
        });
    }
    Ok(entries)
}

/// Return lower directory entries as `(name, file type)` pairs.
fn read_lower_entries(dir: &Path) -> ZResult<Vec<(String, fs::FileType)>> {
    let rd = fs::read_dir(dir).map_err(|e| crate::zerr!("read {}: {e}", dir.display()))?;
    let mut entries = Vec::new();
    for entry in rd {
        let entry = entry.map_err(|e| crate::zerr!("read entry in {}: {e}", dir.display()))?;
        let file_type = entry
            .file_type()
            .map_err(|e| crate::zerr!("file_type in {}: {e}", dir.display()))?;
        entries.push((entry.file_name().to_string_lossy().into_owned(), file_type));
    }
    Ok(entries)
}

/// Turn a relative rootfs path into its conventional absolute display path.
fn absolute_path(rel: &Path) -> PathBuf {
    let mut path = PathBuf::from("/");
    path.push(rel);
    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;

    fn temp_root(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zerun-diff-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn make_whiteout(path: &Path) {
        let target = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        let rc = unsafe { libc::mknod(target.as_ptr(), libc::S_IFCHR | 0o600, 0) };
        assert_eq!(
            rc,
            0,
            "mknod {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }

    fn changes_as_map(changes: &[Change]) -> HashMap<PathBuf, ChangeKind> {
        changes.iter().map(|c| (c.path.clone(), c.kind)).collect()
    }

    #[test]
    fn classifies_upper_files_and_directories() {
        let lower = temp_root("added-lower");
        let upper = temp_root("added-upper");
        fs::create_dir_all(lower.join("kept")).unwrap();
        fs::write(lower.join("changed.txt"), b"old").unwrap();
        fs::create_dir_all(upper.join("kept")).unwrap();
        fs::write(upper.join("changed.txt"), b"new").unwrap();
        fs::write(upper.join("added.txt"), b"new").unwrap();

        let changes = diff_roots(&lower, &upper).unwrap();
        let map = changes_as_map(&changes);
        assert_eq!(
            map.get(Path::new("/changed.txt")),
            Some(&ChangeKind::Changed)
        );
        assert_eq!(map.get(Path::new("/added.txt")), Some(&ChangeKind::Added));
        assert_eq!(map.get(Path::new("/kept")), Some(&ChangeKind::Changed));
    }

    #[test]
    fn whiteouts_mark_lower_entries_deleted() {
        let lower = temp_root("whiteout-lower");
        let upper = temp_root("whiteout-upper");
        fs::write(lower.join("old.conf"), b"old").unwrap();
        make_whiteout(&upper.join(".wh.old.conf"));
        make_whiteout(&upper.join(".wh.missing"));

        let changes = diff_roots(&lower, &upper).unwrap();
        assert_eq!(
            changes,
            vec![Change {
                kind: ChangeKind::Deleted,
                path: PathBuf::from("/old.conf"),
            }]
        );
    }

    #[test]
    fn opaque_whiteout_hides_lower_children() {
        let lower = temp_root("opaque-lower");
        let upper = temp_root("opaque-upper");
        fs::create_dir_all(lower.join("logs")).unwrap();
        fs::write(lower.join("logs/old.log"), b"old").unwrap();
        fs::create_dir_all(upper.join("logs")).unwrap();
        make_whiteout(&upper.join("logs/.wh..wh..opq"));
        fs::write(upper.join("logs/new.log"), b"new").unwrap();

        let changes = diff_roots(&lower, &upper).unwrap();
        let map = changes_as_map(&changes);
        assert_eq!(
            map.get(Path::new("/logs/old.log")),
            Some(&ChangeKind::Deleted)
        );
        assert_eq!(
            map.get(Path::new("/logs/new.log")),
            Some(&ChangeKind::Added)
        );
        assert_eq!(map.get(Path::new("/logs")), Some(&ChangeKind::Changed));
    }

    #[test]
    fn missing_roots_are_rejected_clearly() {
        let lower = temp_root("missing-lower");
        let upper = temp_root("missing-upper");
        fs::remove_dir_all(&lower).unwrap();
        let err = diff_roots(&lower, &upper).unwrap_err();
        assert!(err.to_string().contains("lower rootfs"));
    }
}
