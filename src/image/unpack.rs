//! OCI layer application: unpack a (decompressed) tar stream into a rootfs
//! directory, honoring whiteouts and guarding against path traversal.
//!
//! The OCI `diff_id` (sha256 of the whole uncompressed stream) is deliberately
//! NOT computed here: a streaming tar parser reads lazily and may not consume
//! trailing padding, so callers hash the full decompressed stream themselves
//! (see `pull::spool_layer`).
use crate::error::ZResult;
use crate::fsutil;
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

const WHITEOUT_PREFIX: &str = ".wh.";
const OPAQUE_WHITEOUT: &str = ".wh..wh..opq";

/// Unpack `reader` (a tar stream) below `root`, applying whiteouts.
/// `media_hint` is only used in error messages.
pub fn unpack_layer<R: Read>(reader: R, root: &Path, media_hint: &str) -> ZResult<()> {
    let mut archive = tar::Archive::new(reader);
    let entries = archive
        .entries()
        .map_err(|e| crate::zerr!("read tar stream ({media_hint}): {e}"))?;

    for entry in entries {
        let mut entry = entry.map_err(|e| crate::zerr!("read tar entry ({media_hint}): {e}"))?;
        let header = entry.header().clone();
        let raw_path = entry
            .path()
            .map_err(|e| crate::zerr!("bad tar entry path ({media_hint}): {e}"))?;
        let Some(rel) = sanitize_rel_path(&raw_path) else {
            eprintln!(
                "zerun: warn: skipping unsafe tar path {:?} (traversal/absolute)",
                raw_path.as_os_str()
            );
            continue;
        };
        if rel.as_os_str().is_empty() {
            continue; // the archive root itself
        }

        // Whiteout handling operates on the parent directory.
        let name = rel
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let parent_rel = rel.parent().unwrap_or_else(|| Path::new(""));
        let parent_abs = safe_join(root, parent_rel)?;

        if name == OPAQUE_WHITEOUT {
            remove_all_children(&parent_abs);
            continue;
        }
        if name.starts_with(".wh..wh..") {
            // Other whiteout bookkeeping entries (.plnk etc.): ignore.
            continue;
        }
        if let Some(rest) = name.strip_prefix(WHITEOUT_PREFIX) {
            if !rest.is_empty() {
                let victim = safe_join(root, &parent_rel.join(rest))?;
                fsutil::remove_dir_all_quiet(&victim);
                let _ = fs::remove_file(&victim); // in case it was a file/symlink
            }
            continue;
        }

        apply_entry(&mut entry, &header, root, &rel, &parent_abs, media_hint)?;
    }

    Ok(())
}

fn apply_entry<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    header: &tar::Header,
    root: &Path,
    rel: &Path,
    parent_abs: &Path,
    media_hint: &str,
) -> ZResult<()> {
    let dest = safe_join(root, rel)?;
    let kind = header.entry_type();
    fs::create_dir_all(parent_abs).map_err(|e| {
        crate::zerr!(
            "create parent {} for {}: {e}",
            parent_abs.display(),
            rel.display()
        )
    })?;

    match kind {
        tar::EntryType::Directory => {
            fs::create_dir_all(&dest).map_err(|e| crate::zerr!("mkdir {}: {e}", dest.display()))?;
            set_mode_if_possible(&dest, header.mode()?);
        }
        tar::EntryType::Regular | tar::EntryType::Continuous => {
            // Replace a directory of the same name (overlay semantics).
            if dest.is_dir() {
                fsutil::remove_dir_all_quiet(&dest);
            }
            let mut f = fs::File::create(&dest)
                .map_err(|e| crate::zerr!("create {}: {e}", dest.display()))?;
            io::copy(entry, &mut f).map_err(|e| crate::zerr!("write {}: {e}", dest.display()))?;
            set_mode_if_possible(&dest, header.mode()?);
        }
        tar::EntryType::Symlink => {
            if dest.is_dir() {
                fsutil::remove_dir_all_quiet(&dest);
            }
            let target = header
                .link_name()
                .map_err(|e| crate::zerr!("bad symlink target in {rel:?}: {e}"))?
                .ok_or_else(|| crate::zerr!("symlink {rel:?} has no target"))?;
            let _ = fs::remove_file(&dest);
            std::os::unix::fs::symlink(&target, &dest).map_err(|e| {
                crate::zerr!("symlink {} -> {}: {e}", dest.display(), target.display())
            })?;
        }
        tar::EntryType::Link => {
            let target_name = header
                .link_name()
                .map_err(|e| crate::zerr!("bad hardlink target in {rel:?}: {e}"))?
                .ok_or_else(|| crate::zerr!("hardlink {rel:?} has no target"))?;
            let target_abs = safe_join(root, &target_name)?;
            if dest.exists() {
                let _ = fs::remove_file(&dest);
            }
            fs::hard_link(&target_abs, &dest).map_err(|e| {
                crate::zerr!(
                    "hardlink {} -> {}: {e}",
                    dest.display(),
                    target_abs.display()
                )
            })?;
        }
        _ => {
            // Devices, fifos and sockets cannot be created unprivileged and are
            // essentially absent from container images.
            eprintln!(
                "zerun: warn: skipping special file {} ({media_hint})",
                rel.display()
            );
        }
    }
    Ok(())
}

/// Convert a tar path to a safe relative path. Returns None for absolute paths,
/// parent traversal, or empty results.
fn sanitize_rel_path(p: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::Normal(c) => out.push(c),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Join `rel` below `root`, refusing any intermediate symlink that escapes root.
fn safe_join(root: &Path, rel: &Path) -> ZResult<PathBuf> {
    let mut cur = root.to_path_buf();
    for comp in rel.components() {
        match comp {
            Component::Normal(c) => {
                let next = cur.join(c);
                // Reject escaping through a symlinked intermediate directory.
                if let Ok(md) = fs::symlink_metadata(&next) {
                    if md.file_type().is_symlink() {
                        let target = fs::canonicalize(&next)
                            .map_err(|e| crate::zerr!("resolve symlink {}: {e}", next.display()))?;
                        let root_canon =
                            fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
                        if !target.starts_with(&root_canon) {
                            return Err(crate::zerr!(
                                "refusing path {}: intermediate symlink escapes the rootfs",
                                rel.display()
                            ));
                        }
                        // Resolve: continue from the symlink target directory.
                        cur = target;
                        continue;
                    }
                }
                cur = next;
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(crate::zerr!("unsafe path component in {rel:?}"));
            }
        }
    }
    Ok(cur)
}

fn set_mode_if_possible(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(p, fs::Permissions::from_mode(mode & 0o7777));
}

fn remove_all_children(dir: &Path) {
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                fsutil::remove_dir_all_quiet(&p);
            } else {
                let _ = fs::remove_file(&p);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tar_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (path, content) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            b.append_data(&mut header, path, &content[..]).unwrap();
        }
        b.into_inner().unwrap()
    }

    #[test]
    fn unpacks_files_and_is_idempotent() {
        let dir = std::env::temp_dir().join(format!("zerun-unpack-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let bytes = tar_bytes(&[("etc/hello.txt", b"world"), ("bin/tool", b"#!/bin/sh\n")]);
        unpack_layer(&bytes[..], &dir, "test").unwrap();
        assert_eq!(
            fs::read_to_string(dir.join("etc/hello.txt")).unwrap(),
            "world"
        );
        assert_eq!(
            fs::read_to_string(dir.join("bin/tool")).unwrap(),
            "#!/bin/sh\n"
        );
        // Re-applying the same layer over an existing root is idempotent.
        unpack_layer(&bytes[..], &dir, "test").unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn whiteout_removes_existing_file() {
        let dir = std::env::temp_dir().join(format!("zerun-whiteout-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("etc")).unwrap();
        fs::write(dir.join("etc/old.conf"), b"old").unwrap();

        let bytes = tar_bytes(&[("etc/.wh.old.conf", b""), ("etc/new.conf", b"new")]);
        unpack_layer(&bytes[..], &dir, "test").unwrap();
        assert!(!dir.join("etc/old.conf").exists());
        assert_eq!(fs::read_to_string(dir.join("etc/new.conf")).unwrap(), "new");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn opaque_whiteout_clears_directory() {
        let dir = std::env::temp_dir().join(format!("zerun-opq-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("var/log")).unwrap();
        fs::write(dir.join("var/log/old.log"), b"old").unwrap();

        let bytes = tar_bytes(&[("var/log/.wh..wh..opq", b""), ("var/log/new.log", b"new")]);
        unpack_layer(&bytes[..], &dir, "test").unwrap();
        assert!(!dir.join("var/log/old.log").exists());
        assert_eq!(
            fs::read_to_string(dir.join("var/log/new.log")).unwrap(),
            "new"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn traversal_paths_are_rejected() {
        // `unpack_layer` sanitizes every path before touching the filesystem;
        // the tar writer itself refuses `..`, so exercise the sanitizer.
        assert!(sanitize_rel_path(Path::new("../evil")).is_none());
        assert!(sanitize_rel_path(Path::new("/etc/passwd")).is_none());
        assert!(sanitize_rel_path(Path::new("a/../../b")).is_none());
        assert!(sanitize_rel_path(Path::new("./ok")).is_some());
        assert_eq!(
            sanitize_rel_path(Path::new("usr/bin/tool")).unwrap(),
            Path::new("usr/bin/tool")
        );
    }
}
