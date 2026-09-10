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
use std::io::{self, BufRead, Read, Write};
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
    let (manifest_digest, manifest_bytes) = resolve_single_manifest(
        store,
        client,
        &endpoints,
        &reference.registry,
        repo,
        &req_ref,
        &want,
    )?;
    let manifest = match manifest::classify(&manifest_bytes)? {
        ImageDoc::Manifest(m) => m,
        ImageDoc::Index(_) => unreachable!("resolve_single_manifest returns single manifests"),
    };

    // 2. Config blob: download if missing, parse it.
    ensure_blob(
        store,
        client,
        &endpoints,
        &reference.registry,
        repo,
        &manifest.config.digest,
    )?;
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
    let rootfs = materialize_rootfs(
        store,
        client,
        &endpoints,
        &reference.registry,
        repo,
        &manifest,
        &config,
    )?;

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
    registry: &str,
    repo: &str,
    req_ref: &str,
    want: &Platform,
) -> ZResult<(String, Vec<u8>)> {
    let mut last_err: Option<ZError> = None;
    for base in endpoints {
        let top_url = format!("{base}/v2/{repo}/manifests/{req_ref}");
        let res = (|| -> ZResult<(String, Vec<u8>)> {
            let resp = client.get(&top_url, Some(manifest::ACCEPT_MANIFEST), registry, repo)?;
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
                        client.get(&child_url, Some(manifest::ACCEPT_MANIFEST), registry, repo)?;
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
    registry: &str,
    repo: &str,
    digest: &str,
) -> ZResult<()> {
    if store.has_blob(digest) {
        return Ok(());
    }
    let mut last_err: Option<ZError> = None;
    for base in endpoints {
        let url = format!("{base}/v2/{repo}/blobs/{digest}");
        match client.get(&url, None, registry, repo) {
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

/// Download all manifest blobs (if needed), then materialize the rootfs from
/// the local blob store.
fn materialize_rootfs(
    store: &ImageStore,
    client: &mut RegistryClient,
    endpoints: &[String],
    registry: &str,
    repo: &str,
    manifest: &manifest::Manifest,
    config: &ImageConfig,
) -> ZResult<std::path::PathBuf> {
    for (i, layer) in manifest.layers.iter().enumerate() {
        println!(
            "  layer {}/{}: {} ({})",
            i + 1,
            manifest.layers.len(),
            short_digest(&layer.digest),
            crate::fsutil::human_size(layer.size)
        );
        ensure_blob(store, client, endpoints, registry, repo, &layer.digest)?;
    }
    materialize_local_rootfs(store, manifest, config)
}

/// Unpack all locally stored layers (in order) into the content-addressed
/// rootfs directory. Unpacking goes to a temp dir first and is renamed into
/// place only on success, so a failed/interrupted operation never leaves a
/// half-built rootfs behind.
pub(crate) fn materialize_local_rootfs(
    store: &ImageStore,
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

/// Open a stored layer blob for decompressed reading.
///
/// Dispatch is media-type first (OCI/Docker names); when the media type is
/// unknown or missing we fall back to sniffing the compression magic bytes, so
/// a correctly compressed layer still unpacks even if registry metadata is
/// wrong. Chunked variants (`zstd:chunked`) use a different framing and get a
/// clear error instead of silent corruption.
pub(crate) fn open_layer_reader(path: &Path, media_type: &str) -> ZResult<Box<dyn Read>> {
    let file = File::open(path).map_err(|e| crate::zerr!("open layer {}: {e}", path.display()))?;
    let mut reader = io::BufReader::new(file);

    if media_type.contains("chunked") {
        return Err(crate::zerr!(
            "chunked layer compression is not supported (media type '{media_type}')"
        ));
    }
    if media_type.contains("zstd") {
        return zstd_decoder(reader);
    }
    if media_type.contains("gzip") {
        return gzip_decoder(reader);
    }
    // Unknown media type: peek without consuming, then pick a decoder.
    let head = match reader.fill_buf() {
        Ok(h) => h.to_vec(),
        Err(e) => return Err(crate::zerr!("read layer header: {e}")),
    };
    if head.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return zstd_decoder(reader);
    }
    if head.starts_with(&[0x1f, 0x8b]) {
        return gzip_decoder(reader);
    }
    Ok(Box::new(reader))
}

fn gzip_decoder<R: Read + 'static>(reader: R) -> ZResult<Box<dyn Read>> {
    Ok(Box::new(GzDecoder::new(reader)))
}

fn zstd_decoder<R: Read + 'static>(reader: R) -> ZResult<Box<dyn Read>> {
    zstd::stream::read::Decoder::new(reader)
        .map(|d| Box::new(d) as Box<dyn Read>)
        .map_err(|e| crate::zerr!("open zstd layer: {e}"))
}

/// Abbreviate a `sha256:<hex>` digest for human progress output.
fn short_digest(digest: &str) -> String {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    let keep = hex.len().min(12);
    format!("sha256:{}", &hex[..keep])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn temp_blob(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "zerun-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&p, bytes).unwrap();
        p
    }

    fn read_all(mut r: Box<dyn Read>) -> Vec<u8> {
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn missing_file_errors_regardless_of_media_type() {
        let p = Path::new("/nonexistent");
        for mt in [
            "application/vnd.docker.image.rootfs.diff.tar.gzip",
            "application/vnd.oci.image.layer.v1.tar+zstd",
            "application/vnd.oci.image.layer.v1.tar",
        ] {
            assert!(open_layer_reader(p, mt).is_err());
        }
    }

    #[test]
    fn gzip_and_zstd_layers_decode_by_media_type() {
        let plain = b"hello uncompressed layer\n";
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut gz = gz;
        use std::io::Write;
        gz.write_all(plain).unwrap();
        let gz_bytes = gz.finish().unwrap();

        let zstd_bytes = zstd::stream::encode_all(&plain[..], 3).unwrap();

        let gp = temp_blob("gzip", &gz_bytes);
        let zp = temp_blob("zstd", &zstd_bytes);
        let g =
            open_layer_reader(&gp, "application/vnd.docker.image.rootfs.diff.tar.gzip").unwrap();
        assert_eq!(read_all(g), plain);
        let z = open_layer_reader(&zp, "application/vnd.oci.image.layer.v1.tar+zstd").unwrap();
        assert_eq!(read_all(z), plain);
        let _ = std::fs::remove_file(&gp);
        let _ = std::fs::remove_file(&zp);
    }

    #[test]
    fn unknown_media_type_sniffs_compression_magic() {
        let plain = b"sniffed layer\n";
        let gz_bytes = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut gz = gz_bytes;
        use std::io::Write;
        gz.write_all(plain).unwrap();
        let gz_bytes = gz.finish().unwrap();
        let zstd_bytes = zstd::stream::encode_all(&plain[..], 3).unwrap();

        let gp = temp_blob("sniff-gzip", &gz_bytes);
        let zp = temp_blob("sniff-zstd", &zstd_bytes);
        let tp = temp_blob("plain", plain);
        assert_eq!(
            read_all(open_layer_reader(&gp, "application/octet-stream").unwrap()),
            plain
        );
        assert_eq!(
            read_all(open_layer_reader(&zp, "application/octet-stream").unwrap()),
            plain
        );
        assert_eq!(
            read_all(open_layer_reader(&tp, "application/octet-stream").unwrap()),
            plain
        );
        for p in [&gp, &zp, &tp] {
            let _ = std::fs::remove_file(p);
        }
    }

    #[test]
    fn chunked_zstd_gets_a_clear_error() {
        let p = temp_blob("chunked", b"whatever");
        let err = match open_layer_reader(&p, "application/vnd.oci.image.layer.v1.tar+zstd+chunked")
        {
            Ok(_) => panic!("chunked zstd should be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("chunked"));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn short_digest_abbreviates() {
        assert_eq!(
            short_digest("sha256:abcdef1234567890"),
            "sha256:abcdef123456"
        );
        assert_eq!(short_digest("not-a-digest"), "sha256:not-a-digest");
    }
}
