//! Build a local OCI image from a container rootfs (`zerun commit`).
//!
//! Zerun materializes image layers into a merged rootfs, so the simplest
//! robust commit is a whole-rootfs layer. That avoids trying to infer a diff
//! against an arbitrary base image and remains valid for `--no-overlay` and
//! legacy-rootfs containers. The resulting single-layer image is valid OCI
//! schema 2 on disk and can be run and removed through the normal image store.
use crate::error::ZResult;
use crate::fsutil;
use crate::image::manifest::host_platform;
use crate::image::name::Reference;
use crate::image::store::ImageStore;
use crate::image::unpack::unpack_layer;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MANIFEST_MEDIA_TYPE: &str = "application/vnd.docker.distribution.manifest.v2+json";
const CONFIG_MEDIA_TYPE: &str = "application/vnd.docker.container.image.v1+json";
const LAYER_MEDIA_TYPE: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";
const OPAQUE_WHITEOUT: &str = ".wh..wh..opq";

/// Runtime metadata to record in the committed image config.
#[derive(Debug, Clone, Default)]
pub struct CommitOptions {
    /// Full `KEY=VALUE` container environment from lifecycle state.
    pub env: Vec<String>,
    /// Full command from lifecycle state (flattens entrypoint/cmd).
    pub cmd: Vec<String>,
    pub working_dir: String,
    /// Container user (`config.User` in the committed image).
    pub user: Option<String>,
    pub comment: Option<String>,
    pub author: Option<String>,
}

/// Create a whole-rootfs, single-layer local image and tag it.
pub fn commit_image(
    store: &ImageStore,
    source_rootfs: &Path,
    target: &str,
    options: CommitOptions,
) -> ZResult<crate::image::store::ImageRecord> {
    if !source_rootfs.is_dir() {
        return Err(crate::zerr!(
            "container rootfs does not exist: {}",
            source_rootfs.display()
        ));
    }
    let reference = Reference::parse(target)?;
    if reference.digest.is_some() {
        return Err(crate::zerr!(
            "commit target must be REPOSITORY[:TAG], not a digest reference"
        ));
    }

    // Build the layer in a temporary file, then atomically install it by its
    // compressed sha256. The uncompressed sha256 becomes the OCI diff_id.
    let layer_tmp = store.blob_tmp("commit-layer");
    fsutil::remove_dir_all_quiet(&layer_tmp); // directory form if an old failure left it
    let _ = fs::remove_file(&layer_tmp);
    let (diff_id, _uncompressed_size) = create_layer(source_rootfs, &layer_tmp)?;
    let (layer_digest, layer_size) = store.install_blob_file(&layer_tmp)?;

    // The image config is content-addressed and also names the rootfs dir.
    let config = build_config_json(&options, &diff_id);
    let config_bytes = serde_json::to_vec_pretty(&config)
        .map_err(|e| crate::zerr!("serialize committed config: {e}"))?;
    let config_digest = format!("sha256:{}", crate::image::store::sha256_hex(&config_bytes));
    store.write_blob(&config_digest, &config_bytes)?;

    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "config": {
            "mediaType": CONFIG_MEDIA_TYPE,
            "size": config_bytes.len(),
            "digest": config_digest,
        },
        "layers": [{
            "mediaType": LAYER_MEDIA_TYPE,
            "size": layer_size,
            "digest": layer_digest,
        }],
    });
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| crate::zerr!("serialize committed manifest: {e}"))?;
    let manifest_digest = format!(
        "sha256:{}",
        crate::image::store::sha256_hex(&manifest_bytes)
    );
    store.write_blob(&manifest_digest, &manifest_bytes)?;

    materialize_rootfs(store, &config_digest, &layer_digest)?;

    let total_size = layer_size + config_bytes.len() as u64 + manifest_bytes.len() as u64;
    let name = format!("{}/{}", reference.registry, reference.repository);
    store.add_image(
        &name,
        reference.tag.as_deref(),
        &manifest_digest,
        &config_digest,
        total_size,
    )?;
    store
        .find_record(&name, reference.tag.as_deref(), None)?
        .ok_or_else(|| crate::zerr!("committed image vanished before it could be reported"))
}

/// Rebuild an exited overlay container's filesystem from its base rootfs and
/// upper layer. Once the container's mount namespace exits, the kernel unmounts
/// the merged view and leaves an empty mount-point directory behind.
pub fn rebuild_rootfs(base_rootfs: &Path, upper: &Path, staging: &Path) -> ZResult<PathBuf> {
    fsutil::remove_dir_all_quiet(staging);
    let result = fsutil::copy_dir_all(base_rootfs, staging)
        .and_then(|()| apply_overlay_upper(staging, upper));
    if let Err(e) = result {
        fsutil::remove_dir_all_quiet(staging);
        return Err(e);
    }
    Ok(staging.to_path_buf())
}

/// Apply overlay upper-layer semantics onto `root`.
///
/// OverlayFS stores deletion markers as character devices named `.wh.<name>`;
/// `.wh..wh..opq` makes the directory opaque. Regular upper entries replace the
/// corresponding lower entry.
fn apply_overlay_upper(root: &Path, upper: &Path) -> ZResult<()> {
    use std::os::unix::fs::FileTypeExt;

    fs::create_dir_all(root).map_err(|e| crate::zerr!("create merged rootfs: {e}"))?;
    let entries: Vec<_> = fs::read_dir(upper)
        .map_err(|e| crate::zerr!("read overlay upper {}: {e}", upper.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| crate::zerr!("read overlay upper {}: {e}", upper.display()))?;

    for entry in &entries {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == OPAQUE_WHITEOUT && entry.file_type()?.is_char_device() {
            remove_children(root);
            break;
        }
    }

    for entry in entries {
        let from = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let ft = entry.file_type()?;
        let to = root.join(entry.file_name());

        if ft.is_char_device() && name.starts_with(".wh.") {
            if let Some(victim_name) = name.strip_prefix(".wh.") {
                let victim = root.join(victim_name);
                fsutil::remove_dir_all_quiet(&victim);
                let _ = fs::remove_file(&victim);
            }
            continue;
        }
        if name.starts_with(".wh..wh..") {
            continue;
        }

        if ft.is_dir() {
            fs::create_dir_all(&to)
                .map_err(|e| crate::zerr!("create upper dir {}: {e}", to.display()))?;
            apply_overlay_upper(&to, &from)?;
            copy_dir_mode(&from, &to);
        } else if ft.is_symlink() {
            if to.is_dir() {
                fsutil::remove_dir_all_quiet(&to);
            }
            let _ = fs::remove_file(&to);
            let target = fs::read_link(&from)
                .map_err(|e| crate::zerr!("read upper symlink {}: {e}", from.display()))?;
            std::os::unix::fs::symlink(&target, &to)
                .map_err(|e| crate::zerr!("create upper symlink {}: {e}", to.display(),))?;
        } else if ft.is_file() {
            if to.is_dir() {
                fsutil::remove_dir_all_quiet(&to);
            }
            let _ = fs::remove_file(&to);
            fs::copy(&from, &to)
                .map_err(|e| crate::zerr!("copy upper file {}: {e}", from.display()))?;
            copy_dir_mode(&from, &to);
        } else {
            eprintln!(
                "zerun: warn: skipping overlay upper special file {}",
                from.display()
            );
        }
    }
    Ok(())
}

fn remove_children(dir: &Path) {
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

fn copy_dir_mode(from: &Path, to: &Path) {
    if let Ok(meta) = fs::symlink_metadata(from) {
        let _ = fs::set_permissions(to, fs::Permissions::from_mode(meta.mode() & 0o7777));
    }
}

fn create_layer(source_rootfs: &Path, compressed_path: &Path) -> ZResult<(String, u64)> {
    let file = File::create(compressed_path)
        .map_err(|e| crate::zerr!("create committed layer temp: {e}"))?;
    let encoder = GzEncoder::new(file, Compression::new(6));
    let mut hash_writer = HashWriter::new(encoder);
    let mut builder = tar::Builder::new(&mut hash_writer);
    // Preserve links exactly as they appear; following them would fail on
    // common rootfs links such as /etc/mtab -> ../proc/mounts.
    builder.follow_symlinks(false);
    builder
        .append_dir_all(Path::new(""), source_rootfs)
        .map_err(|e| crate::zerr!("archive {}: {e}", source_rootfs.display()))?;
    builder
        .finish()
        .map_err(|e| crate::zerr!("finish committed layer tar: {e}"))?;
    drop(builder); // release the mutable borrow before unwrapping the hasher

    let HashWriter {
        inner: encoder,
        hasher,
    } = hash_writer;
    let diff = hex(&hasher.finalize());
    let file = encoder
        .finish()
        .map_err(|e| crate::zerr!("finish committed layer gzip: {e}"))?;
    file.sync_all()
        .map_err(|e| crate::zerr!("sync committed layer: {e}"))?;
    let size = file
        .metadata()
        .map_err(|e| crate::zerr!("stat committed layer: {e}"))?
        .len();
    Ok((format!("sha256:{diff}"), size))
}

struct HashWriter<W: Write> {
    inner: W,
    hasher: Sha256,
}

impl<W: Write> HashWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }
}

impl<W: Write> Write for HashWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn build_config_json(options: &CommitOptions, diff_id: &str) -> serde_json::Value {
    let platform = host_platform();
    let created = crate::state::now_rfc3339();
    let mut config = serde_json::json!({
        "created": created,
        "architecture": platform.architecture,
        "os": platform.os,
        "config": {
            "Env": options.env,
            "Cmd": options.cmd,
            "WorkingDir": options.working_dir,
        },
        "rootfs": {
            "type": "layers",
            "diff_ids": [diff_id],
        },
        "history": [{
            "created": created,
            "created_by": "zerun commit",
        }],
    });
    if let Some(user) = &options.user {
        config["config"]["User"] = serde_json::Value::String(user.clone());
    }
    if let Some(comment) = &options.comment {
        config["history"][0]["comment"] = serde_json::Value::String(comment.clone());
    }
    if let Some(author) = &options.author {
        config["author"] = serde_json::Value::String(author.clone());
    }
    config
}

/// Make the committed image immediately runnable through the normal lookup
/// path, which expects a materialized rootfs keyed by the config digest.
fn materialize_rootfs(store: &ImageStore, config_digest: &str, layer_digest: &str) -> ZResult<()> {
    let final_dir = store.rootfs_path(config_digest)?;
    if final_dir.is_dir() {
        return Ok(());
    }
    let tmp = store.rootfs_tmp(config_digest)?;
    fsutil::remove_dir_all_quiet(&tmp);
    fs::create_dir_all(&tmp).map_err(|e| crate::zerr!("create committed rootfs staging: {e}"))?;

    let result = File::open(store.blob_path(layer_digest)?)
        .map_err(|e| crate::zerr!("open committed layer {layer_digest}: {e}"))
        .and_then(|file| unpack_layer(flate2::read::GzDecoder::new(file), &tmp, layer_digest));
    if let Err(e) = result {
        fsutil::remove_dir_all_quiet(&tmp);
        return Err(e);
    }

    match fs::rename(&tmp, &final_dir) {
        Ok(()) => Ok(()),
        Err(_) if final_dir.is_dir() => {
            fsutil::remove_dir_all_quiet(&tmp);
            Ok(())
        }
        Err(e) => {
            fsutil::remove_dir_all_quiet(&tmp);
            Err(crate::zerr!("install committed rootfs: {e}"))
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn test_rootfs() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zerun-commit-rootfs-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("bin")).unwrap();
        fs::create_dir_all(dir.join("etc")).unwrap();
        fs::write(dir.join("bin/committed-marker"), b"yes").unwrap();
        std::os::unix::fs::symlink("../proc/mounts", dir.join("etc/mtab")).unwrap();
        dir
    }

    #[test]
    fn commits_a_valid_whole_rootfs_image() {
        let data_dir = std::env::temp_dir().join(format!(
            "zerun-commit-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&data_dir);
        let store = ImageStore::at(&data_dir).unwrap();
        let source = test_rootfs();
        let options = CommitOptions {
            env: vec!["PATH=/usr/bin".to_string()],
            cmd: vec!["/bin/committed-marker".to_string()],
            working_dir: "/".to_string(),
            user: Some("1000:1000".to_string()),
            comment: Some("test snapshot".to_string()),
            author: Some("TheSkyC <0x4fe6@gmail.com>".to_string()),
        };
        let record = commit_image(&store, &source, "example/zerun:v1", options).unwrap();

        assert_eq!(record.name, "docker.io/example/zerun");
        assert_eq!(record.tag.as_deref(), Some("v1"));
        let manifest_bytes = store.read_blob(&record.manifest).unwrap().unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
        assert_eq!(manifest["schemaVersion"], 2);
        assert_eq!(manifest["mediaType"], MANIFEST_MEDIA_TYPE);
        assert_eq!(manifest["layers"].as_array().unwrap().len(), 1);

        let config_digest = record.config.as_str();
        let config_bytes = store.read_blob(config_digest).unwrap().unwrap();
        let config: serde_json::Value = serde_json::from_slice(&config_bytes).unwrap();
        assert_eq!(config["config"]["Env"][0], "PATH=/usr/bin");
        assert_eq!(config["config"]["Cmd"][0], "/bin/committed-marker");
        assert_eq!(config["config"]["User"], "1000:1000");
        assert_eq!(config["author"], "TheSkyC <0x4fe6@gmail.com>");
        assert_eq!(config["history"][0]["comment"], "test snapshot");

        let rootfs = store.rootfs_path(config_digest).unwrap();
        assert_eq!(
            fs::read(rootfs.join("bin/committed-marker")).unwrap(),
            b"yes"
        );

        let layer_digest = manifest["layers"][0]["digest"].as_str().unwrap();
        let layer_bytes = store.read_blob(layer_digest).unwrap().unwrap();
        let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(&layer_bytes[..]));
        let names: Vec<_> = tar
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_path_buf())
            .collect();
        assert!(names.contains(&std::path::PathBuf::from("bin/committed-marker")));

        assert!(commit_image(
            &store,
            &source,
            "example/zerun@sha256:0000000000000000000000000000000000000000000000000000000000000000",
            CommitOptions::default()
        )
        .is_err());
        let _ = fs::remove_dir_all(&data_dir);
    }
}
