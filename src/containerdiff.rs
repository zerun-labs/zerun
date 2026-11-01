//! Container filesystem diffs against the image's materialized lower root.
//!
//! Detached containers keep their OverlayFS `upper` directory, and live
//! containers expose the same writable layer to the host. Rather than walking
//! the mounted root (which contains mounts and merged results), inspect
//! OverlayFS semantics directly: upper entries are additions/changes while
//! whiteouts and opaque-directory xattrs identify deleted lower entries.
use crate::error::ZResult;
use crate::syscalls;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const WHITEOUT_PREFIX: &str = ".wh.";
const OPAQUE_WHITEOUT: &str = ".wh..wh..opq";
const TRUSTED_WHITEOUT_XATTR: &str = "trusted.overlay.whiteout";
const USER_WHITEOUT_XATTR: &str = "user.overlay.whiteout";
const TRUSTED_OPAQUE_XATTR: &str = "trusted.overlay.opaque";
const USER_OPAQUE_XATTR: &str = "user.overlay.opaque";

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
/// test output. Deleted descendants of an opaque directory are represented by
/// the immediate lower child, as Docker does.
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

        let opaque = entries.iter().any(|entry| entry.name == OPAQUE_WHITEOUT)
            || has_opaque_xattr(&upper_dir)?;
        if opaque {
            for (name, _) in read_lower_entries(&lower_dir)? {
                if upper_names.contains(&name) {
                    continue; // a later upper entry overrides the opaque deletion
                }
                let path = absolute_path(&rel.join(name));
                changes.insert(path, ChangeKind::Deleted);
            }
        }

        for entry in entries {
            if is_whiteout(&entry) {
                let victim = entry
                    .name
                    .strip_prefix(WHITEOUT_PREFIX)
                    .unwrap_or(&entry.name)
                    .to_string();
                if !victim.is_empty() && fs::symlink_metadata(lower_dir.join(&victim)).is_ok() {
                    changes.insert(absolute_path(&rel.join(&victim)), ChangeKind::Deleted);
                }
                continue;
            }

            let Entry {
                name,
                file_type: entry_type,
                ..
            } = entry;
            if name == OPAQUE_WHITEOUT {
                continue;
            }
            let child_rel = rel.join(&name);
            let upper_path = upper_dir.join(&name);
            let lower_path = lower_dir.join(&name);

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
    /// A zero-length regular file carrying an OverlayFS whiteout xattr.
    xattr_whiteout: bool,
}

/// Recognize the forms Zerun may encounter:
/// - live OverlayFS whiteouts are character devices named after their victim;
/// - OCI-style whiteout markers are named `.wh.<victim>`;
/// - `userxattr` overlays may use zero-length files with a whiteout xattr.
fn is_whiteout(entry: &Entry) -> bool {
    (entry.file_type.is_char_device()
        && (entry.name.starts_with(WHITEOUT_PREFIX) || entry.rdev == Some(0)))
        || entry.xattr_whiteout
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
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|e| crate::zerr!("stat {}: {e}", entry.path().display()))?;
        let rdev = file_type.is_char_device().then(|| metadata.rdev());
        let xattr_whiteout = file_type.is_file()
            && metadata.len() == 0
            && (has_xattr(&entry.path(), TRUSTED_WHITEOUT_XATTR)?
                || has_xattr(&entry.path(), USER_WHITEOUT_XATTR)?);
        entries.push(Entry {
            name,
            file_type,
            rdev,
            xattr_whiteout,
        });
    }
    Ok(entries)
}

/// Live OverlayFS marks a directory opaque with an `opaque=y` (or `opaque=x`
/// for the whiteout-xattr optimization) xattr. The `user.*` namespace is used
/// by mounts created with `userxattr` for unprivileged use.
fn has_opaque_xattr(dir: &Path) -> ZResult<bool> {
    for name in [TRUSTED_OPAQUE_XATTR, USER_OPAQUE_XATTR] {
        if let Some(value) = syscalls::get_xattr(dir, name)? {
            if value == b"y" || value == b"x" {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn has_xattr(path: &Path, name: &str) -> ZResult<bool> {
    Ok(syscalls::get_xattr(path, name)?.is_some())
}

/// Return lower directory entries as `(name, file type)` pairs.
fn read_lower_entries(dir: &Path) -> ZResult<Vec<(String, fs::FileType)>> {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        // An opaque upper directory may replace a lower file, or it may be a
        // newly-created directory with no lower counterpart. Neither case has
        // lower children to report.
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT) | Some(libc::ENOTDIR)) => {
            return Ok(Vec::new());
        }
        Err(e) => return Err(crate::zerr!("read {}: {e}", dir.display())),
    };
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
        crate::syscalls::mknod_char(path, 0, 0, 0o600)
            .unwrap_or_else(|error| panic!("mknod {}: {error}", path.display()));
    }

    fn make_xattr_whiteout(path: &Path) {
        fs::write(path, b"").unwrap();
        crate::syscalls::set_xattr(path, USER_WHITEOUT_XATTR, b"y")
            .unwrap_or_else(|error| panic!("set whiteout xattr {}: {error}", path.display()));
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
        fs::write(lower.join("xattr.conf"), b"old").unwrap();
        make_whiteout(&upper.join(".wh.old.conf"));
        make_xattr_whiteout(&upper.join("xattr.conf"));
        make_whiteout(&upper.join(".wh.missing"));

        let changes = diff_roots(&lower, &upper).unwrap();
        assert_eq!(
            changes,
            vec![
                Change {
                    kind: ChangeKind::Deleted,
                    path: PathBuf::from("/old.conf"),
                },
                Change {
                    kind: ChangeKind::Deleted,
                    path: PathBuf::from("/xattr.conf"),
                },
            ]
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
        fs::create_dir_all(upper.join("fresh")).unwrap();
        make_whiteout(&upper.join("fresh/.wh..wh..opq"));
        fs::write(upper.join("fresh/file"), b"new").unwrap();

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
        assert_eq!(map.get(Path::new("/fresh")), Some(&ChangeKind::Added));
        assert_eq!(map.get(Path::new("/fresh/file")), Some(&ChangeKind::Added));
    }

    #[test]
    fn overlay_opaque_xattr_hides_lower_children() {
        let lower = temp_root("opaque-xattr-lower");
        let upper = temp_root("opaque-xattr-upper");
        fs::create_dir_all(lower.join("cache")).unwrap();
        fs::write(lower.join("cache/old"), b"old").unwrap();
        fs::create_dir_all(lower.join("cache/nested")).unwrap();
        fs::write(lower.join("cache/nested/file"), b"old").unwrap();
        fs::create_dir_all(upper.join("cache")).unwrap();
        fs::write(upper.join("cache/new"), b"new").unwrap();
        crate::syscalls::set_xattr(upper.join("cache"), USER_OPAQUE_XATTR, b"y")
            .expect("set opaque xattr");

        let changes = diff_roots(&lower, &upper).unwrap();
        let map = changes_as_map(&changes);
        assert_eq!(map.get(Path::new("/cache")), Some(&ChangeKind::Changed));
        assert_eq!(map.get(Path::new("/cache/old")), Some(&ChangeKind::Deleted));
        assert_eq!(
            map.get(Path::new("/cache/nested")),
            Some(&ChangeKind::Deleted)
        );
        assert_eq!(map.get(Path::new("/cache/new")), Some(&ChangeKind::Added));
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
