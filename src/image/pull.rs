//! Pull orchestration: resolve a reference to a single-architecture manifest,
//! download + verify all blobs, materialize the rootfs, and index the tag.
//!
//! Endpoint fallback works at two levels:
//! - manifest resolution retries across every endpoint (mirrors then official);
//! - blob downloads retry across every endpoint too (a caching mirror may miss).
use crate::error::{ZError, ZResult};
use crate::fsutil;
use crate::image::config::ImageConfig;
use crate::image::manifest::{self, ImageDoc, Platform};
use crate::image::name::Reference;
use crate::image::registry::RegistryClient;
use crate::image::store::{sha256_hex, ImageStore};
use crate::image::unpack::unpack_layer;
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct PullOptions {
    /// Platform override (`os/arch[/variant]`); defaults to the host platform.
    pub platform: Option<String>,
}

/// What a successful pull produced (also what `run IMAGE` consumes).
#[derive(Debug)]
pub struct PulledImage {
    /// Materialized read-only rootfs directory.
    pub rootfs: std::path::PathBuf,
    pub config: ImageConfig,
    pub size_bytes: u64,
}

/// Locate an already-pulled image locally (no network). Returns the read-only
/// rootfs directory and the parsed image config, or `None` when not present.
pub fn local_image(
    store: &ImageStore,
    reference: &Reference,
) -> ZResult<Option<(std::path::PathBuf, ImageConfig)>> {
    let name = format!("{}/{}", reference.registry, reference.repository);
    let Some(rec) =
        store.find_record(&name, reference.tag.as_deref(), reference.digest.as_deref())?
    else {
        return Ok(None);
    };
    let rootfs = store.rootfs_path(&rec.config)?;
    if !rootfs.is_dir() {
        return Err(crate::zerr!(
            "image {} is recorded but its rootfs is missing; re-pull it",
            reference.canonical()
        ));
    }
    let cfg_bytes = store
        .read_blob(&rec.config)?
        .ok_or_else(|| crate::zerr!("image {} config blob is missing", reference.canonical()))?;
    let config = ImageConfig::parse(&cfg_bytes)?;
    Ok(Some((rootfs, config)))
}

pub fn pull_image(
    store: &ImageStore,
    client: &mut RegistryClient,
    reference: &Reference,
    opts: &PullOptions,
) -> ZResult<PulledImage> {
    let want = opts
        .platform
        .as_deref()
        .map(Platform::parse)
        .transpose()?
        .unwrap_or_else(manifest::host_platform);
    let endpoints = client.endpoints(&reference.registry);
    let repo = &reference.repository;
    let req_ref = reference.digest.clone().unwrap_or_else(|| {
        reference
            .tag
            .clone()
            .unwrap_or_else(|| "latest".to_string())
    });

    // 1. Resolve the tag/digest to a single-architecture manifest on the first
    //    endpoint that answers (mirrors first, official last).
    let (manifest_digest, manifest_bytes) =
        resolve_single_manifest(store, client, &endpoints, repo, &req_ref, &want)?;
    let manifest = match manifest::classify(&manifest_bytes)? {
        ImageDoc::Manifest(m) => m,
        ImageDoc::Index(_) => unreachable!("resolve_single_manifest returns single manifests"),
    };

    // 2. Config blob: download if missing, parse it.
    ensure_blob(store, client, &endpoints, repo, &manifest.config.digest)?;
    let cfg_bytes = store
        .read_blob(&manifest.config.digest)?
        .ok_or_else(|| crate::zerr!("config blob disappeared after download"))?;
    let config = ImageConfig::parse(&cfg_bytes)?;

    // 3. Platform sanity: a manifest without a platform field gets resolved via
    //    the index, so a mismatch here means the config disagrees with the
    //    manifest's own platform (very rare, but free to check).
    if !config.architecture.is_empty() && !config.os.is_empty() {
        let got_arch = config.architecture.clone();
        let got_os = config.os.clone();
        if got_arch != want.architecture || got_os != want.os {
            return Err(crate::zerr!(
                "image config platform {got_os}/{got_arch} does not match requested {}/{}",
                want.os,
                want.architecture
            ));
        }
    }

    // 4. Materialize the rootfs (keyed by config digest, shared across tags).
    let size_bytes: u64 = manifest.layers.iter().map(|l| l.size).sum();
    let rootfs = materialize_rootfs(store, client, &endpoints, repo, &manifest, &config)?;

    // 5. Index under name[:tag] (a digest-pinned pull records no tag).
    let name = format!("{}/{}", reference.registry, reference.repository);
    let tag = if reference.digest.is_some() {
        None
    } else {
        Some(
            reference
                .tag
                .clone()
                .unwrap_or_else(|| "latest".to_string()),
        )
    };
    store.add_image(
        &name,
        tag.as_deref(),
        &manifest_digest,
        &manifest.config.digest,
        size_bytes,
    )?;

    Ok(PulledImage {
        rootfs,
        config,
        size_bytes,
    })
}

/// Fetch the manifest for `req_ref` (tag or digest), following a multi-arch
/// index to the child manifest matching `want`. Returns the *single* manifest's
/// bytes and digest, stored into the blob store.
fn resolve_single_manifest(
    store: &ImageStore,
    client: &mut RegistryClient,
    endpoints: &[String],
    repo: &str,
    req_ref: &str,
    want: &Platform,
) -> ZResult<(String, Vec<u8>)> {
    let mut last_err: Option<ZError> = None;
    for base in endpoints {
        let top_url = format!("{base}/v2/{repo}/manifests/{req_ref}");
        let res = (|| -> ZResult<(String, Vec<u8>)> {
            let resp = client.get(&top_url, Some(manifest::ACCEPT_MANIFEST), repo)?;
            let digest_hdr = resp.header("docker-content-digest").map(str::to_string);
            let bytes = resp
                .into_string()
                .map_err(|e| crate::zerr!("read manifest body: {e}"))?
                .into_bytes();
            match manifest::classify(&bytes)? {
                ImageDoc::Manifest(_) => {
                    let digest = store_manifest(store, digest_hdr.as_deref(), &bytes)?;
                    Ok((digest, bytes))
                }
                ImageDoc::Index(index) => {
                    let doc = ImageDoc::Index(index);
                    let child = doc.select(want)?.ok_or_else(|| {
                        crate::zerr!("index resolution returned no child manifest")
                    })?;
                    let child_digest = child.digest.clone();
                    let child_url = format!("{base}/v2/{repo}/manifests/{child_digest}");
                    let child_resp =
                        client.get(&child_url, Some(manifest::ACCEPT_MANIFEST), repo)?;
                    let child_bytes = child_resp
                        .into_string()
                        .map_err(|e| crate::zerr!("read child manifest body: {e}"))?
                        .into_bytes();
                    let digest = store_manifest(store, Some(&child_digest), &child_bytes)?;
                    Ok((digest, child_bytes))
                }
            }
        })();
        match res {
            Ok(v) => return Ok(v),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err
        .unwrap_or_else(|| crate::zerr!("no registry endpoint reachable for {repo}:{req_ref}")))
}

/// Store manifest bytes under `digest` (or compute it when the registry did not
/// send a digest header), verifying content matches.
fn store_manifest(store: &ImageStore, digest: Option<&str>, bytes: &[u8]) -> ZResult<String> {
    let digest = match digest {
        Some(d) => {
            let actual = sha256_hex(bytes);
            if d != format!("sha256:{actual}") {
                return Err(crate::zerr!(
                    "manifest digest mismatch: registry said {d}, body is sha256:{actual}"
                ));
            }
            d.to_string()
        }
        None => format!("sha256:{}", sha256_hex(bytes)),
    };
    store.write_blob(&digest, bytes)?;
    Ok(digest)
}

/// Download a blob from the first endpoint that serves it, verifying sha256.
fn ensure_blob(
    store: &ImageStore,
    client: &mut RegistryClient,
    endpoints: &[String],
    repo: &str,
    digest: &str,
) -> ZResult<()> {
    if store.has_blob(digest) {
        return Ok(());
    }
    let mut last_err: Option<ZError> = None;
    for base in endpoints {
        let url = format!("{base}/v2/{repo}/blobs/{digest}");
        match client.get(&url, None, repo) {
            Ok(resp) => {
                let reader = resp.into_reader();
                match store.store_blob_stream(digest, reader) {
                    Ok(()) => return Ok(()),
                    Err(e) => last_err = Some(e),
                }
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| crate::zerr!("no endpoint served blob {digest}")))
}

/// Unpack all layers (in order) into the content-addressed rootfs directory.
/// Unpacking goes to a temp dir first and is renamed into place only on success,
/// so a failed/interrupted pull never leaves a half-built rootfs behind.
fn materialize_rootfs(
    store: &ImageStore,
    client: &mut RegistryClient,
    endpoints: &[String],
    repo: &str,
    manifest: &manifest::Manifest,
    config: &ImageConfig,
) -> ZResult<std::path::PathBuf> {
    let config_digest = &manifest.config.digest;
    let final_dir = store.rootfs_path(config_digest)?;
    if final_dir.is_dir() {
        return Ok(final_dir);
    }
    if config.rootfs.diff_ids.len() != manifest.layers.len() {
        return Err(crate::zerr!(
            "image config lists {} layers but the manifest has {}",
            config.rootfs.diff_ids.len(),
            manifest.layers.len()
        ));
    }

    let tmp = store.rootfs_tmp(config_digest)?;
    fsutil::remove_dir_all_quiet(&tmp);
    fs::create_dir_all(&tmp).map_err(|e| crate::zerr!("create rootfs staging dir: {e}"))?;
    for (i, layer) in manifest.layers.iter().enumerate() {
        ensure_blob(store, client, endpoints, repo, &layer.digest)?;
        let blob_path = store.blob_path(&layer.digest)?;
        let expected_diff = config.rootfs.diff_ids[i].clone();
        let hint = format!("layer {} ({})", i + 1, layer.digest);

        // Decompress once into a spool file while hashing the *entire*
        // uncompressed stream (the OCI diff_id). Unpacking then reads the spool;
        // hashing and unpacking must not share one lazy reader because the tar
        // parser does not consume trailing archive padding.
        let (spool, actual_diff) = match spool_layer(store, &blob_path, &layer.media_type, i) {
            Ok(v) => v,
            Err(e) => {
                fsutil::remove_dir_all_quiet(&tmp);
                return Err(e);
            }
        };
        let diff_ok = format!("sha256:{actual_diff}") == expected_diff;
        if diff_ok {
            let res = unpack_layer(File::open(&spool)?, &tmp, &hint);
            fsutil::remove_dir_all_quiet(&spool);
            if let Err(e) = res {
                fsutil::remove_dir_all_quiet(&tmp);
                return Err(e);
            }
        } else {
            fsutil::remove_dir_all_quiet(&spool);
            fsutil::remove_dir_all_quiet(&tmp);
            return Err(crate::zerr!(
                "diff_id mismatch on {hint}: config says {expected_diff}, decompressed sha256:{actual_diff}"
            ));
        }
    }
    // Rename into place. If another process won the race, drop our copy.
    match fs::rename(&tmp, &final_dir) {
        Ok(()) => Ok(final_dir),
        Err(_) if final_dir.is_dir() => {
            fsutil::remove_dir_all_quiet(&tmp);
            Ok(final_dir)
        }
        Err(e) => {
            fsutil::remove_dir_all_quiet(&tmp);
            Err(crate::zerr!("install rootfs: {e}"))
        }
    }
}

/// Decompress a stored layer blob into a spool file under the image store,
/// hashing the full decompressed stream. Returns (spool path, diff_id hex).
fn spool_layer(
    store: &ImageStore,
    blob_path: &Path,
    media_type: &str,
    index: usize,
) -> ZResult<(std::path::PathBuf, String)> {
    let reader = open_layer_reader(blob_path, media_type)?;
    let spool = store
        .rootfs_dir()
        .join(format!(".tmp-spool-{}-{index}", std::process::id()));
    let mut out = File::create(&spool).map_err(|e| crate::zerr!("create layer spool: {e}"))?;
    let mut hasher = Sha256::new();
    let mut reader = reader;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| crate::zerr!("decompress layer: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        out.write_all(&buf[..n])
            .map_err(|e| crate::zerr!("write layer spool: {e}"))?;
    }
    Ok((spool, hex(&hasher.finalize())))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Wrap a stored layer blob in a decompressor matching its media type.
fn open_layer_reader(path: &Path, media_type: &str) -> ZResult<Box<dyn Read>> {
    if media_type.contains("zstd") {
        return Err(crate::zerr!(
            "zstd-compressed layers are not supported yet (media type '{media_type}')"
        ));
    }
    let file = File::open(path).map_err(|e| crate::zerr!("open layer {}: {e}", path.display()))?;
    if media_type.contains("gzip") {
        Ok(Box::new(GzDecoder::new(file)))
    } else {
        Ok(Box::new(file))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer_media_type_dispatch() {
        let p = Path::new("/nonexistent");
        assert!(open_layer_reader(p, "application/vnd.docker.image.rootfs.diff.tar.gzip").is_err()); // file missing, not media issue
        assert!(open_layer_reader(p, "application/vnd.oci.image.layer.v1.tar+zstd").is_err());
    }
}
