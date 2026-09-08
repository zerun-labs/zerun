//! Filesystem helpers used by the store and the rootfs layer.
use crate::error::ZResult;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Recursively copy `src` into `dst` (which is created if missing).
///
/// Semantics chosen for container rootfs copies:
/// - symlinks are recreated, never followed;
/// - file modes are preserved;
/// - sockets, fifos and device nodes are skipped with a warning (unprivileged
///   users cannot create them and images rarely contain them).
pub fn copy_dir_all(src: &Path, dst: &Path) -> ZResult<()> {
    if !src.is_dir() {
        return Err(crate::zerr!(
            "copy source is not a directory: {}",
            src.display()
        ));
    }
    fs::create_dir_all(dst).map_err(|e| crate::zerr!("create {}: {e}", dst.display()))?;
    let meta = fs::symlink_metadata(src)?;
    set_mode(dst, meta.mode() & 0o7777)?;

    for entry in fs::read_dir(src).map_err(|e| crate::zerr!("read_dir {}: {e}", src.display()))? {
        let entry = entry.map_err(|e| crate::zerr!("read_dir entry: {e}"))?;
        let name = entry.file_name();
        let from = entry.path();
        let to = dst.join(&name);
        let ft = entry
            .file_type()
            .map_err(|e| crate::zerr!("file_type {}: {e}", from.display()))?;
        if ft.is_dir() {
            copy_dir_all(&from, &to)?;
        } else if ft.is_symlink() {
            let target = fs::read_link(&from)?;
            if let Err(e) = std::os::unix::fs::symlink(&target, &to) {
                eprintln!(
                    "zerun: warn: skip symlink {} -> {}: {e}",
                    from.display(),
                    target.display()
                );
            }
        } else if ft.is_file() {
            fs::copy(&from, &to)
                .map_err(|e| crate::zerr!("copy {} -> {}: {e}", from.display(), to.display()))?;
            let m = fs::symlink_metadata(&from)?;
            set_mode(&to, m.mode() & 0o7777)?;
        } else {
            eprintln!(
                "zerun: warn: skip special file {} (not a regular file/symlink/dir)",
                from.display()
            );
        }
    }
    Ok(())
}

fn set_mode(p: &Path, mode: u32) -> ZResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(mode))
        .map_err(|e| crate::zerr!("chmod {}: {e}", p.display()))
}

/// Atomic file write: write to a temp file in the same directory, then rename.
/// Crash-safe for the file-based state this project relies on.
#[allow(dead_code)] // used by the image store milestone
pub fn atomic_write(path: &Path, data: &[u8]) -> ZResult<()> {
    let dir = path
        .parent()
        .ok_or_else(|| crate::zerr!("no parent for {}", path.display()))?;
    fs::create_dir_all(dir).map_err(|e| crate::zerr!("mkdir {}: {e}", dir.display()))?;
    let tmp = dir.join(format!(
        ".tmp-{}-{}",
        std::process::id(),
        path.file_name().and_then(|n| n.to_str()).unwrap_or("state")
    ));
    fs::write(&tmp, data).map_err(|e| crate::zerr!("write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        crate::zerr!("rename {} -> {}: {e}", tmp.display(), path.display())
    })?;
    Ok(())
}

/// Remove a directory tree, tolerating a missing root (used for container fs
/// cleanup after runs).
pub fn remove_dir_all_quiet(p: &Path) {
    if let Err(e) = remove_rec(p) {
        if e.kind() != std::io::ErrorKind::NotFound {
            eprintln!("zerun: warn: cleanup {} failed: {e}", p.display());
        }
    }
}

fn remove_rec(p: &Path) -> std::io::Result<()> {
    let meta = match fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if !meta.file_type().is_dir() {
        return fs::remove_file(p);
    }
    // Fast path: empty directory (works even with mode 000).
    match fs::remove_dir(p) {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => {}
    }
    // Non-empty: recurse, then remove the directory itself.
    let rd = fs::read_dir(p)?;
    for entry in rd {
        let entry = entry?;
        remove_rec(&entry.path())?;
    }
    fs::remove_dir(p)
}

/// Best-effort create-all parents.
pub fn mkdir_p(p: &Path) -> ZResult<()> {
    fs::create_dir_all(p).map_err(|e| crate::zerr!("mkdir {}: {e}", p.display()))
}

/// A tiny cache of absolute canonical paths so callers avoid repeating
/// canonicalization. (Reserved for future use.)
#[allow(dead_code)]
pub fn canonical_or_self(p: &Path) -> PathBuf {
    fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}
/// Render a byte count for humans ("3.7 MB"); used in CLI progress output.
pub fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_size_rounds() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1024), "1.0 KB");
        assert_eq!(human_size(3_700_000), "3.5 MB");
    }
}
