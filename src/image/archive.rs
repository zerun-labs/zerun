//! OCI image layout archives for `zerun save` / `zerun load`.
//!
//! The archive format is the standard OCI image layout tarball:
//!
//!   oci-layout                      {"imageLayoutVersion": "1.0.0"}
//!   index.json                      OCI index of the exported manifests
//!   blobs/sha256/<hex>              content-addressed manifest/config/layer blobs
//!
//! `save` writes one archive holding every image requested; `load` streams the
//! tarball into the local blob store (each digest is verified on the way in),
//! then materializes rootfs trees and re-creates tag index records. Layer
//! content is shared across tags by digest, exactly like a registry pull.
use crate::error::ZResult;
use crate::fsutil;
use crate::image::config::ImageConfig;
use crate::image::manifest::{self, ImageDoc};
use crate::image::name::Reference;
use crate::image::pull::materialize_local_rootfs;
use crate::image::store::{digest_hex, ImageRecord, ImageStore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Component, Path, PathBuf};

const OCI_LAYOUT_VERSION: &str = "1.0.0";
const OCI_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
const MANIFEST_MEDIA_TYPE: &str = "application/vnd.docker.distribution.manifest.v2+json";
const REF_NAME_ANNOTATION: &str = "org.opencontainers.image.ref.name";

/// Serialize a set of locally tagged images to an OCI image layout tarball at
/// `output`. Returns the records that were exported, in argument order.
pub fn save_images(
    store: &ImageStore,
    images: &[String],
    output: &Path,
) -> ZResult<Vec<ImageRecord>> {
    if images.is_empty() {
        return Err(crate::zerr!("at least one IMAGE is required"));
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|e| crate::zerr!("create output directory {}: {e}", parent.display()))?;
    let tmp_tar = parent.join(format!(
        ".{}.tmp-{}",
        output
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("image.tar"),
        std::process::id()
    ));
    let layout = parent.join(format!(".zerun-save-layout-{}", std::process::id()));
    let _ = fs::remove_file(&tmp_tar);
    fsutil::remove_dir_all_quiet(&layout);

    let result = (|| -> ZResult<Vec<ImageRecord>> {
        fs::create_dir_all(layout.join("blobs").join("sha256"))
            .map_err(|e| crate::zerr!("create archive layout: {e}"))?;
        let mut exported = Vec::new();
        let mut descriptors = Vec::new();
        let mut copied = BTreeSet::new();

        for raw in images {
            let reference =
                Reference::parse(raw).map_err(|e| crate::zerr!("invalid image '{raw}': {e}"))?;
            let name = format!("{}/{}", reference.registry, reference.repository);
            let record = store
                .find_record(&name, reference.tag.as_deref(), reference.digest.as_deref())?
                .ok_or_else(|| crate::zerr!("No such image: {raw}"))?;

            copy_manifest_tree(store, &layout, &record.manifest, &mut copied)?;
            let bytes = store
                .read_blob(&record.manifest)?
                .ok_or_else(|| crate::zerr!("manifest blob {} is missing", record.manifest))?;
            let mut annotations = HashMap::new();
            if let Some(tag) = &record.tag {
                annotations.insert(REF_NAME_ANNOTATION.to_string(), format!("{name}:{tag}"));
            }
            descriptors.push(ArchiveDescriptor {
                media_type: manifest_media_type(&bytes)?,
                digest: record.manifest.clone(),
                size: bytes.len() as u64,
                annotations,
            });
            exported.push(record);
        }

        let index = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_INDEX_MEDIA_TYPE,
            "manifests": descriptors,
        });
        let layout_doc = serde_json::json!({
            "imageLayoutVersion": OCI_LAYOUT_VERSION,
        });
        fsutil::atomic_write(
            &layout.join("oci-layout"),
            layout_doc.to_string().as_bytes(),
        )?;
        fsutil::atomic_write(&layout.join("index.json"), index.to_string().as_bytes())?;

        let file = File::create(&tmp_tar)
            .map_err(|e| crate::zerr!("create {}: {e}", tmp_tar.display()))?;
        let mut builder = tar::Builder::new(file);
        builder
            .append_dir_all("", &layout)
            .map_err(|e| crate::zerr!("write OCI archive: {e}"))?;
        builder
            .into_inner()
            .map_err(|e| crate::zerr!("finish OCI archive: {e}"))?
            .sync_all()
            .map_err(|e| crate::zerr!("sync OCI archive: {e}"))?;
        fs::rename(&tmp_tar, output)
            .map_err(|e| crate::zerr!("install archive {}: {e}", output.display()))?;
        Ok(exported)
    })();

    fsutil::remove_dir_all_quiet(&layout);
    let _ = fs::remove_file(&tmp_tar);
    result
}

/// Recursively copy a manifest (and its config/layers, or child manifests for
/// an index) into the archive layout. `copied` prevents duplicate blobs.
fn copy_manifest_tree(
    store: &ImageStore,
    layout: &Path,
    digest: &str,
    copied: &mut BTreeSet<String>,
) -> ZResult<()> {
    if !copied.insert(digest.to_string()) {
        return Ok(());
    }
    let bytes = store
        .read_blob(digest)?
        .ok_or_else(|| crate::zerr!("blob {digest} is missing from the image store"))?;
    copy_blob_to_layout(layout, digest, &bytes)?;
    match manifest::classify(&bytes)? {
        ImageDoc::Manifest(m) => {
            copy_blob_to_layout(
                layout,
                &m.config.digest,
                &store_blob(store, &m.config.digest)?,
            )?;
            for layer in &m.layers {
                copy_blob_to_layout(layout, &layer.digest, &store_blob(store, &layer.digest)?)?;
            }
        }
        ImageDoc::Index(index) => {
            for child in &index.manifests {
                copy_manifest_tree(store, layout, &child.digest, copied)?;
            }
        }
    }
    Ok(())
}

fn store_blob(store: &ImageStore, digest: &str) -> ZResult<Vec<u8>> {
    store
        .read_blob(digest)?
        .ok_or_else(|| crate::zerr!("blob {digest} is missing from the image store"))
}

fn copy_blob_to_layout(layout: &Path, digest: &str, bytes: &[u8]) -> ZResult<()> {
    let hex = digest_hex(digest)?;
    fsutil::atomic_write(&layout.join("blobs").join("sha256").join(hex), bytes)
}

fn manifest_media_type(bytes: &[u8]) -> ZResult<String> {
    let v: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| crate::zerr!("parse manifest media type: {e}"))?;
    Ok(v.get("mediaType")
        .and_then(|m| m.as_str())
        .unwrap_or(MANIFEST_MEDIA_TYPE)
        .to_string())
}

/// Load an OCI image layout tarball into the image store, materializing rootfs
/// trees and re-creating tag index records. Returns every newly imported
/// record. Existing tags with the same name are replaced (re-load semantics).
pub fn load_archive(store: &ImageStore, input: &Path) -> ZResult<Vec<ImageRecord>> {
    let file =
        File::open(input).map_err(|e| crate::zerr!("open archive {}: {e}", input.display()))?;
    let mut archive = tar::Archive::new(BufReader::new(file));
    let mut layout_ok = false;
    let mut index_bytes: Option<Vec<u8>> = None;
    let entries = archive
        .entries()
        .map_err(|e| crate::zerr!("read archive {}: {e}", input.display()))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| crate::zerr!("read archive entry: {e}"))?;
        if entry.header().entry_type().is_dir() {
            continue;
        }
        let raw_path = entry
            .path()
            .map_err(|e| crate::zerr!("read archive entry path: {e}"))?
            .to_path_buf();
        let path: PathBuf = raw_path.components().collect();
        if path.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(crate::zerr!(
                "unsafe path in archive: {}",
                raw_path.display()
            ));
        }
        let name = path
            .to_str()
            .ok_or_else(|| crate::zerr!("non-UTF-8 path in archive: {}", raw_path.display()))?;
        match name {
            "oci-layout" => {
                let mut bytes = Vec::new();
                entry
                    .read_to_end(&mut bytes)
                    .map_err(|e| crate::zerr!("read oci-layout: {e}"))?;
                let doc: OciLayout = serde_json::from_slice(&bytes)
                    .map_err(|e| crate::zerr!("invalid oci-layout json: {e}"))?;
                if doc.image_layout_version != OCI_LAYOUT_VERSION {
                    return Err(crate::zerr!(
                        "unsupported OCI layout version '{}'",
                        doc.image_layout_version
                    ));
                }
                layout_ok = true;
            }
            "index.json" => {
                let mut bytes = Vec::new();
                entry
                    .read_to_end(&mut bytes)
                    .map_err(|e| crate::zerr!("read index.json: {e}"))?;
                index_bytes = Some(bytes);
            }
            _ => {
                let Some(rest) = name.strip_prefix("blobs/sha256/") else {
                    return Err(crate::zerr!(
                        "unsupported archive entry '{}' (not an OCI image layout)",
                        name
                    ));
                };
                if rest.is_empty()
                    || rest.contains('/')
                    || !rest.bytes().all(|b| b.is_ascii_hexdigit())
                    || rest.len() != 64
                {
                    return Err(crate::zerr!("invalid blob path in archive: '{}'", name));
                }
                let digest = format!("sha256:{rest}");
                store.store_blob_stream(&digest, &mut entry)?;
            }
        }
    }

    if !layout_ok {
        return Err(crate::zerr!(
            "archive is missing oci-layout (not an OCI image layout)"
        ));
    }
    let index_bytes = index_bytes.ok_or_else(|| crate::zerr!("archive is missing index.json"))?;
    let index: OciIndex = serde_json::from_slice(&index_bytes)
        .map_err(|e| crate::zerr!("invalid index.json: {e}"))?;
    if index.manifests.is_empty() {
        return Err(crate::zerr!("archive contains no images"));
    }

    let mut imported = Vec::new();
    for descriptor in &index.manifests {
        let ref_name = descriptor
            .annotations
            .get(REF_NAME_ANNOTATION)
            .map(String::as_str);
        imported.extend(import_descriptor(store, &descriptor.digest, ref_name)?);
    }
    Ok(imported)
}

/// Import one manifest (or the host-platform child of an index) and create its
/// tag index record. Rootfs materialization happens here so the image is
/// immediately runnable, exactly like a pull.
fn import_descriptor(
    store: &ImageStore,
    digest: &str,
    ref_name: Option<&str>,
) -> ZResult<Vec<ImageRecord>> {
    let bytes = store_blob(store, digest)?;
    match manifest::classify(&bytes)? {
        ImageDoc::Manifest(m) => Ok(vec![import_manifest(store, digest, &bytes, &m, ref_name)?]),
        ImageDoc::Index(index) => {
            let doc = ImageDoc::Index(index);
            let child = doc.select(&manifest::host_platform())?.ok_or_else(|| {
                crate::zerr!(
                    "archive index has no manifest for {}/{}",
                    manifest::host_platform().os,
                    manifest::host_platform().architecture
                )
            })?;
            // A ref name written on the outer index applies to its platform
            // child; digest-only index children without a name are imported as
            // digest-pinned records so they do not shadow each other.
            import_descriptor(store, &child.digest, ref_name)
        }
    }
}

fn import_manifest(
    store: &ImageStore,
    digest: &str,
    bytes: &[u8],
    manifest: &manifest::Manifest,
    ref_name: Option<&str>,
) -> ZResult<ImageRecord> {
    for layer in &manifest.layers {
        if !store.has_blob(&layer.digest) {
            return Err(crate::zerr!(
                "archive is missing layer blob {} referenced by {}",
                layer.digest,
                digest
            ));
        }
    }
    let config_bytes = store_blob(store, &manifest.config.digest)?;
    let config = ImageConfig::parse(&config_bytes)?;
    let _rootfs = materialize_local_rootfs(store, manifest, &config)?;

    let size_bytes: u64 = bytes.len() as u64
        + config_bytes.len() as u64
        + manifest.layers.iter().map(|l| l.size).sum::<u64>();
    let (name, tag) = match ref_name {
        Some(raw) => {
            let reference = Reference::parse(raw)
                .map_err(|e| crate::zerr!("invalid ref name '{raw}' in archive: {e}"))?;
            (
                format!("{}/{}", reference.registry, reference.repository),
                reference.tag.clone(),
            )
        }
        None => {
            // No ref name: keep the manifest importable under an explicit
            // digest-derived tag instead of silently colliding with `latest`.
            let hex = digest_hex(digest)?;
            (
                "docker.io/library/imported".to_string(),
                Some(hex[..12.min(hex.len())].to_string()),
            )
        }
    };
    store.add_image(
        &name,
        tag.as_deref(),
        digest,
        &manifest.config.digest,
        size_bytes,
    )?;
    store
        .find_record(&name, tag.as_deref(), Some(digest))?
        .ok_or_else(|| crate::zerr!("imported image vanished before it could be reported"))
}

#[derive(Debug, Deserialize)]
struct OciLayout {
    #[serde(rename = "imageLayoutVersion")]
    image_layout_version: String,
}

#[derive(Debug, Deserialize)]
struct OciIndex {
    #[serde(default)]
    manifests: Vec<ArchiveDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ArchiveDescriptor {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    digest: String,
    size: u64,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    annotations: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::commit::{commit_image, CommitOptions};
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zerun-{name}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn save_then_load_roundtrips_an_oci_layout_archive() {
        let data_dir = scratch("archive-store");
        let store = ImageStore::at(&data_dir).unwrap();

        let source = scratch("archive-rootfs");
        fs::create_dir_all(source.join("bin")).unwrap();
        fs::write(source.join("bin/archived-marker"), b"yes").unwrap();
        let record = commit_image(
            &store,
            &source,
            "example/zerun-archive:v1",
            CommitOptions {
                env: vec!["PATH=/usr/bin".to_string()],
                cmd: vec!["/bin/archived-marker".to_string()],
                working_dir: "/".to_string(),
                user: None,
                comment: Some("archive round-trip".to_string()),
                author: None,
            },
        )
        .unwrap();

        let archive_path = data_dir.join("export.tar");
        let exported = save_images(
            &store,
            &["example/zerun-archive:v1".to_string()],
            &archive_path,
        )
        .unwrap();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].manifest, record.manifest);

        // Remove the local record, blobs, and rootfs so loading really has to
        // rebuild everything from the archive.
        store
            .remove_record("docker.io/example/zerun-archive", Some("v1"), None)
            .unwrap();
        store.gc().unwrap();

        let imported = load_archive(&store, &archive_path).unwrap();
        assert_eq!(imported.len(), 1);
        let loaded = imported[0].clone();
        assert_eq!(loaded.manifest, record.manifest);
        assert_eq!(loaded.config, record.config);
        let rootfs = store.rootfs_path(&loaded.config).unwrap();
        assert_eq!(
            fs::read(rootfs.join("bin/archived-marker")).unwrap(),
            b"yes"
        );

        let _ = fs::remove_dir_all(&data_dir);
        let _ = fs::remove_dir_all(&source);
    }

    #[test]
    fn load_rejects_foreign_archive_entries() {
        let data_dir = scratch("archive-unsafe");
        let store = ImageStore::at(&data_dir).unwrap();
        let bad = data_dir.join("bad.tar");
        let file = File::create(&bad).unwrap();
        let mut builder = tar::Builder::new(file);
        let mut header = tar::Header::new_gnu();
        header.set_path("evil.txt").unwrap();
        header.set_size(4);
        header.set_cksum();
        builder.append(&header, &b"data"[..]).unwrap();
        builder.into_inner().unwrap();
        assert!(load_archive(&store, &bad).is_err());
        let _ = fs::remove_dir_all(&data_dir);
    }
}
