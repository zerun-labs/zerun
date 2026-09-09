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
                let victim = safe_join_leaf(root, &parent_rel.join(rest))?;
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
    let dest = safe_join_leaf(root, rel)?;
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
            // A directory entry never wipes existing contents (overlay
            // semantics); it only shadows a non-directory of the same name.
            if let Ok(md) = fs::symlink_metadata(&dest) {
                if !md.file_type().is_dir() {
                    let _ = fs::remove_file(&dest); // file or symlink shadowed by a dir
                }
            }
            fs::create_dir_all(&dest).map_err(|e| crate::zerr!("mkdir {}: {e}", dest.display()))?;
            set_mode_if_possible(&dest, header.mode()?);
        }
        tar::EntryType::Regular | tar::EntryType::Continuous => {
            // Replace whatever is already there (overlay semantics) *without*
            // following it: a previous layer's symlink must not redirect this
            // write outside the rootfs.
            if let Ok(md) = fs::symlink_metadata(&dest) {
                if md.file_type().is_dir() {
                    fsutil::remove_dir_all_quiet(&dest);
                } else {
                    let _ = fs::remove_file(&dest); // file or symlink replaced by a file
                }
            }
            let mut f = fs::File::create(&dest)
                .map_err(|e| crate::zerr!("create {}: {e}", dest.display()))?;
            io::copy(entry, &mut f).map_err(|e| crate::zerr!("write {}: {e}", dest.display()))?;
            set_mode_if_possible(&dest, header.mode()?);
        }
        tar::EntryType::Symlink => {
            if let Ok(md) = fs::symlink_metadata(&dest) {
                if md.file_type().is_dir() {
                    fsutil::remove_dir_all_quiet(&dest);
                } else {
                    let _ = fs::remove_file(&dest);
                }
            }
            let target = header
                .link_name()
                .map_err(|e| crate::zerr!("bad symlink target in {rel:?}: {e}"))?
                .ok_or_else(|| crate::zerr!("symlink {rel:?} has no target"))?;
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
            if let Ok(md) = fs::symlink_metadata(&dest) {
                if md.file_type().is_dir() {
                    fsutil::remove_dir_all_quiet(&dest);
                } else {
                    let _ = fs::remove_file(&dest);
                }
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

/// Join `rel` below `root`, resolving symlinked directories *inside the
/// rootfs* (chroot semantics: an absolute link target means below `root`, not
/// below the host `/`). Any component that would escape `root` is refused.
/// The final component is resolved too, so callers get the real directory or
/// file a path refers to.
fn safe_join(root: &Path, rel: &Path) -> ZResult<PathBuf> {
    safe_walk(root, rel, true, 0)
}

/// Like [`safe_join`], but the final component is kept as a literal leaf and
/// never followed. Used for paths we are about to create or remove, where an
/// existing symlink must be replaced/deleted rather than traversed — OCI layers
/// commonly re-declare the same symlink across consecutive layers (e.g.
/// `/etc/nginx/modules -> /usr/lib/nginx/modules`).
fn safe_join_leaf(root: &Path, rel: &Path) -> ZResult<PathBuf> {
    safe_walk(root, rel, false, 0)
}

/// Upper bound on symlink hops while resolving a path (defends loops).
const MAX_SYMLINK_DEPTH: usize = 64;

fn safe_walk(root: &Path, rel: &Path, resolve_last: bool, depth: usize) -> ZResult<PathBuf> {
    if depth > MAX_SYMLINK_DEPTH {
        return Err(crate::zerr!(
            "symlink chain too deep while resolving {rel:?} (loop?)"
        ));
    }
    let root = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let comps: Vec<Component<'_>> = rel.components().collect();
    let mut cur = root.clone();
    let count = comps.len();
    for (i, comp) in comps.iter().enumerate() {
        match comp {
            Component::Normal(c) => {
                let next = cur.join(c);
                let is_last = i + 1 == count;
                cur = if is_last && !resolve_last {
                    next
                } else {
                    resolve_component(&root, &next, rel, depth)?
                };
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(crate::zerr!(
                    "unsafe path component in {rel:?} (must stay under the rootfs)"
                ));
            }
        }
    }
    Ok(cur)
}

/// If `path` is a symlink, resolve the whole chain to its real location inside
/// `root`; otherwise return it unchanged.
fn resolve_component(root: &Path, path: &Path, rel: &Path, depth: usize) -> ZResult<PathBuf> {
    let md = match fs::symlink_metadata(path) {
        Ok(md) => md,
        Err(_) => return Ok(path.to_path_buf()), // does not exist (yet)
    };
    if !md.file_type().is_symlink() {
        return Ok(path.to_path_buf());
    }
    if depth >= MAX_SYMLINK_DEPTH {
        return Err(crate::zerr!(
            "symlink chain too deep while resolving {} (path {rel:?})",
            path.display()
        ));
    }
    let target =
        fs::read_link(path).map_err(|e| crate::zerr!("read symlink {}: {e}", path.display()))?;
    let base = if target.is_absolute() {
        root.to_path_buf()
    } else {
        path.parent().unwrap_or(root).to_path_buf()
    };
    let joined = normalize_under(root, &base, &target).map_err(|e| {
        crate::zerr!(
            "refusing path {rel:?}: symlink {} escapes the rootfs: {e}",
            path.display()
        )
    })?;
    let target_rel = joined.strip_prefix(root).map_err(|_| {
        crate::zerr!(
            "refusing path {rel:?}: symlink {} resolves outside the rootfs",
            path.display()
        )
    })?;
    // Walk the target itself component by component: it may pass through
    // further symlinked directories.
    safe_walk(root, target_rel, true, depth + 1)
}

/// Lexically combine `base` + `target` and require the result to stay under
/// `root`. Absolute `target`s restart at `root` (chroot semantics).
fn normalize_under(root: &Path, base: &Path, target: &Path) -> ZResult<PathBuf> {
    let mut stack: Vec<std::ffi::OsString> = Vec::new();
    let base_rel = base
        .strip_prefix(root)
        .map_err(|_| crate::zerr!("symlink base {} is outside the rootfs", base.display()))?;
    for c in base_rel.components() {
        match c {
            Component::Normal(c) => stack.push(c.to_os_string()),
            Component::CurDir => {}
            Component::ParentDir => {
                if stack.pop().is_none() {
                    return Err(crate::zerr!("path escapes the rootfs"));
                }
            }
            Component::RootDir | Component::Prefix(_) => {}
        }
    }
    for c in target.components() {
        match c {
            Component::RootDir | Component::Prefix(_) => stack.clear(), // absolute: back to root
            Component::CurDir => {}
            Component::ParentDir => {
                if stack.pop().is_none() {
                    return Err(crate::zerr!("path escapes the rootfs"));
                }
            }
            Component::Normal(c) => stack.push(c.to_os_string()),
        }
    }
    let mut out = root.to_path_buf();
    for s in &stack {
        out.push(s);
    }
    Ok(out)
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

    fn make_tar(entries: &[(String, tar::EntryType, Option<String>, Vec<u8>)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (path, ty, link, content) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(*ty);
            header.set_mode(0o755);
            if let Some(l) = link {
                header.set_link_name(l).unwrap();
                header.set_size(0);
            } else {
                header.set_size(content.len() as u64);
            }
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

    #[test]
    fn symlink_redeclared_across_layers_is_replaced_not_followed() {
        let dir = std::env::temp_dir().join(format!(
            "zerun-unpack-symlink-redecl-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let symlink_nginx_modules = (
            "etc/nginx/modules".to_string(),
            tar::EntryType::Symlink,
            Some("/usr/lib/nginx/modules".to_string()),
            b"".to_vec(),
        );
        let l1 = make_tar(&[
            (
                "usr/lib/nginx/modules".to_string(),
                tar::EntryType::Directory,
                None,
                b"".to_vec(),
            ),
            symlink_nginx_modules.clone(),
        ]);
        unpack_layer(&l1[..], &dir, "test").unwrap();

        // A later layer re-declaring the same symlink used to abort: the leaf
        // was canonicalized against the *host* /usr/lib/nginx/modules.
        let l2 = make_tar(&[symlink_nginx_modules]);
        unpack_layer(&l2[..], &dir, "test").unwrap();

        let link = fs::read_link(dir.join("etc/nginx/modules")).unwrap();
        assert_eq!(link, Path::new("/usr/lib/nginx/modules"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn files_below_an_absolute_symlink_land_inside_the_rootfs() {
        let dir =
            std::env::temp_dir().join(format!("zerun-unpack-symlink-abs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let l1 = make_tar(&[
            (
                "usr/lib/nginx/modules".to_string(),
                tar::EntryType::Directory,
                None,
                b"".to_vec(),
            ),
            (
                "etc/nginx/modules".to_string(),
                tar::EntryType::Symlink,
                Some("/usr/lib/nginx/modules".to_string()),
                b"".to_vec(),
            ),
        ]);
        unpack_layer(&l1[..], &dir, "test").unwrap();

        // Writing through the absolute symlink must resolve *inside* the
        // rootfs (chroot semantics), not against the host filesystem.
        let l2 = make_tar(&[(
            "etc/nginx/modules/ngx_http_js_module.so".to_string(),
            tar::EntryType::Regular,
            None,
            b"module".to_vec(),
        )]);
        unpack_layer(&l2[..], &dir, "test").unwrap();

        assert_eq!(
            fs::read(dir.join("usr/lib/nginx/modules/ngx_http_js_module.so")).unwrap(),
            b"module"
        );
        assert!(!Path::new("/usr/lib/nginx/modules/ngx_http_js_module.so").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn relative_symlink_escape_is_rejected() {
        let dir = std::env::temp_dir().join(format!(
            "zerun-unpack-symlink-escape-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let l1 = make_tar(&[(
            "etc/out".to_string(),
            tar::EntryType::Symlink,
            Some("../../escape-me".to_string()),
            b"".to_vec(),
        )]);
        unpack_layer(&l1[..], &dir, "test").unwrap();

        let l2 = make_tar(&[(
            "etc/out/evil".to_string(),
            tar::EntryType::Regular,
            None,
            b"boom".to_vec(),
        )]);
        assert!(unpack_layer(&l2[..], &dir, "test").is_err());
        assert!(!dir.parent().unwrap().join("escape-me").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn symlink_loop_is_rejected() {
        let dir =
            std::env::temp_dir().join(format!("zerun-unpack-symlink-loop-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let l1 = make_tar(&[
            (
                "a".to_string(),
                tar::EntryType::Symlink,
                Some("b".to_string()),
                b"".to_vec(),
            ),
            (
                "b".to_string(),
                tar::EntryType::Symlink,
                Some("a".to_string()),
                b"".to_vec(),
            ),
        ]);
        unpack_layer(&l1[..], &dir, "test").unwrap();

        let l2 = make_tar(&[(
            "a/x".to_string(),
            tar::EntryType::Regular,
            None,
            b"x".to_vec(),
        )]);
        assert!(unpack_layer(&l2[..], &dir, "test").is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
