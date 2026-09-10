//! OCI distribution push.
//!
//! Zerun can push either a selected single-platform image or a complete
//! multi-architecture index retained by `load`. Pushing is a normal OCI
//! distribution transaction: check each referenced blob, start a blob upload
//! when the registry does not already have it, and finally put manifests.
//! Layer files are streamed from disk; they are never buffered wholly in
//! memory.
use crate::error::ZResult;
use crate::image::manifest::{self, Descriptor, ImageDoc};
use crate::image::name::Reference;
use crate::image::registry::RegistryClient;
use crate::image::store::ImageStore;
use std::collections::BTreeSet;
use std::path::Path;

/// Result returned to the CLI after a successful manifest PUT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedImage {
    pub digest: String,
}

pub fn push_image(
    store: &ImageStore,
    client: &mut RegistryClient,
    reference: &Reference,
) -> ZResult<PushedImage> {
    let Some(tag) = reference.tag.as_deref() else {
        return Err(crate::zerr!(
            "push target must be REPOSITORY[:TAG], not a digest reference"
        ));
    };

    let name = format!("{}/{}", reference.registry, reference.repository);
    let Some(record) = store.find_record(&name, Some(tag), None)? else {
        return Err(crate::zerr!("No such image: {}", reference.canonical()));
    };

    // A load-preserved record points `manifest` at the runnable host-platform
    // child and `index` at the complete multi-architecture root. Older/local
    // records have no index and therefore push just the selected manifest.
    let root_digest = record.index.as_deref().unwrap_or(&record.manifest);
    let root_bytes = store
        .read_blob(root_digest)?
        .ok_or_else(|| crate::zerr!("image manifest blob is missing: {root_digest}"))?;
    let actual_root_digest = format!("sha256:{}", crate::image::store::sha256_hex(&root_bytes));
    if actual_root_digest != root_digest {
        return Err(crate::zerr!(
            "local image manifest digest mismatch (record {root_digest}, content {actual_root_digest})"
        ));
    }

    // Validate the complete tree before touching the network. This prevents a
    // partial multi-arch transaction when any platform child is incomplete.
    let mut validated = BTreeSet::new();
    validate_manifest_tree(
        store,
        root_digest,
        &root_bytes,
        &Descriptor {
            media_type: String::new(),
            digest: root_digest.to_string(),
            size: root_bytes.len() as u64,
            platform: None,
        },
        &mut validated,
    )?;

    let base = select_endpoint(client, reference)?;
    let mut pushed = BTreeSet::new();
    let context = PushContext {
        store,
        base: &base,
        reference,
    };
    push_manifest_tree(
        &context,
        client,
        root_digest,
        &root_bytes,
        Some(tag),
        &mut pushed,
    )?;
    Ok(PushedImage {
        digest: root_digest.to_string(),
    })
}

/// Verify a manifest/index and every blob it references before any upload.
fn validate_manifest_tree(
    store: &ImageStore,
    digest: &str,
    bytes: &[u8],
    descriptor: &Descriptor,
    validated: &mut BTreeSet<String>,
) -> ZResult<()> {
    if !validated.insert(digest.to_string()) {
        return Ok(());
    }
    if descriptor.size != 0 && bytes.len() as u64 != descriptor.size {
        return Err(crate::zerr!(
            "manifest {digest} size {} does not match descriptor size {}",
            bytes.len(),
            descriptor.size
        ));
    }
    match manifest::classify(bytes)? {
        ImageDoc::Manifest(m) => {
            let mut blobs = vec![m.config.clone()];
            blobs.extend(m.layers.iter().cloned());
            for blob in blobs {
                let path = store.blob_path(&blob.digest)?;
                verify_blob(&path, blob.size)?;
            }
        }
        ImageDoc::Index(index) => {
            for child in &index.manifests {
                let child_bytes = store.read_blob(&child.digest)?.ok_or_else(|| {
                    crate::zerr!("child manifest blob is missing: {}", child.digest)
                })?;
                let actual = format!("sha256:{}", crate::image::store::sha256_hex(&child_bytes));
                if actual != child.digest {
                    return Err(crate::zerr!(
                        "child manifest digest mismatch (descriptor {}, content {actual})",
                        child.digest
                    ));
                }
                validate_manifest_tree(store, &child.digest, &child_bytes, child, validated)?;
            }
        }
    }
    Ok(())
}

/// Select an API base URL before starting a transaction. For `localhost`, any
/// HTTP response (including 401/404) proves the endpoint is reachable; only
/// transport failures fall through. This avoids retrying every upload against
/// both schemes.
fn select_endpoint(client: &mut RegistryClient, reference: &Reference) -> ZResult<String> {
    let endpoints = client.endpoints(&reference.registry);
    let Some(first) = endpoints.first() else {
        return Err(crate::zerr!("no registry endpoint available"));
    };
    if reference.registry != "localhost" && !reference.registry.starts_with("localhost:") {
        return Ok(first.clone());
    }
    let mut last_error = None;
    for base in endpoints {
        let url = format!("{base}/v2/");
        match client.get(&url, None, &reference.registry, &reference.repository) {
            Ok(_) => return Ok(base),
            Err(e) if e.0.contains("HTTP ") => return Ok(base),
            Err(e) => last_error = Some(e),
        }
    }
    Err(last_error.unwrap_or_else(|| crate::zerr!("no registry endpoint available")))
}

/// Bundles the immutable destination/store inputs for a push traversal.
struct PushContext<'a> {
    store: &'a ImageStore,
    base: &'a str,
    reference: &'a Reference,
}

/// Push all blobs and manifests in an image/index tree to one API base URL.
/// `tag` is attached only to the root; descendants are addressed by digest.
fn push_manifest_tree(
    context: &PushContext<'_>,
    client: &mut RegistryClient,
    digest: &str,
    bytes: &[u8],
    tag: Option<&str>,
    pushed: &mut BTreeSet<String>,
) -> ZResult<()> {
    if !pushed.insert(digest.to_string()) {
        return Ok(());
    }
    match manifest::classify(bytes)? {
        ImageDoc::Manifest(m) => {
            push_manifest_blobs(context.store, client, context.base, context.reference, &m)?;
            put_manifest(
                client,
                context.base,
                context.reference,
                bytes,
                tag.map(str::to_string).as_deref(),
            )?;
        }
        ImageDoc::Index(index) => {
            for child in &index.manifests {
                let child_bytes = context.store.read_blob(&child.digest)?.ok_or_else(|| {
                    crate::zerr!("child manifest blob is missing: {}", child.digest)
                })?;
                let actual = format!("sha256:{}", crate::image::store::sha256_hex(&child_bytes));
                if actual != child.digest {
                    return Err(crate::zerr!(
                        "child manifest digest mismatch (descriptor {}, content {actual})",
                        child.digest
                    ));
                }
                push_manifest_tree(context, client, &child.digest, &child_bytes, None, pushed)?;
            }
            put_manifest(
                client,
                context.base,
                context.reference,
                bytes,
                tag.map(str::to_string).as_deref(),
            )?;
        }
    }
    Ok(())
}

fn push_manifest_blobs(
    store: &ImageStore,
    client: &mut RegistryClient,
    base: &str,
    reference: &Reference,
    manifest: &manifest::Manifest,
) -> ZResult<()> {
    let repo = &reference.repository;
    let registry = &reference.registry;

    let mut descriptors = vec![manifest.config.clone()];
    descriptors.extend(manifest.layers.iter().cloned());
    for descriptor in descriptors {
        let short = short_digest(&descriptor.digest);
        let path = store.blob_path(&descriptor.digest)?;
        let url = format!("{base}/v2/{repo}/blobs/{}", descriptor.digest);
        if client.head(&url, registry, repo)?.is_some() {
            println!("  blob {short}: exists");
            continue;
        }

        match client.start_blob_upload(base, repo, &descriptor.digest)? {
            None => {
                // The registry accepted the complete monolithic POST. This is
                // valid OCI and also saves one round trip on minimal registries.
                println!("  blob {short}: pushed");
            }
            Some(upload_url) => {
                let sep = if upload_url.contains('?') { '&' } else { '?' };
                let upload_url = format!("{upload_url}{sep}digest={}", descriptor.digest);
                if descriptor.digest == manifest.config.digest {
                    let bytes = store.read_blob(&descriptor.digest)?.unwrap_or_default();
                    client.put_blob_bytes(&upload_url, registry, repo, &bytes)?;
                } else {
                    client.put_blob_file(&upload_url, registry, repo, &path)?;
                }
                println!("  blob {short}: pushed");
            }
        }
    }
    Ok(())
}

/// PUT a manifest by tag (root) or by digest (nested manifest/index).
fn put_manifest(
    client: &mut RegistryClient,
    base: &str,
    reference: &Reference,
    bytes: &[u8],
    tag: Option<&str>,
) -> ZResult<()> {
    let repo = &reference.repository;
    let registry = &reference.registry;
    let destination = match tag {
        Some(tag) => tag.to_string(),
        None => format!("sha256:{}", crate::image::store::sha256_hex(bytes)),
    };
    let manifest_url = format!("{base}/v2/{repo}/manifests/{destination}");
    let media_type = serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|v| {
            v.get("mediaType")
                .and_then(|m| m.as_str())
                .map(str::to_string)
        })
        .filter(|m| {
            m.contains("docker.distribution.manifest.v2+json")
                || m.contains("docker.distribution.manifest.list.v2+json")
                || m.contains("oci.image.manifest.v1+json")
                || m.contains("oci.image.index.v1+json")
        })
        .ok_or_else(|| crate::zerr!("unsupported manifest mediaType for push"))?;
    let response = client.put_manifest(&manifest_url, registry, repo, &media_type, bytes)?;
    if let Some(returned) = response.header("docker-content-digest") {
        let expected = format!("sha256:{}", crate::image::store::sha256_hex(bytes));
        if returned != expected {
            return Err(crate::zerr!(
                "registry stored manifest {returned}, expected {expected}"
            ));
        }
    }
    Ok(())
}

fn verify_blob(path: &Path, advertised_size: u64) -> ZResult<()> {
    let metadata = std::fs::metadata(path)
        .map_err(|e| crate::zerr!("local blob {} is missing: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(crate::zerr!("local blob is not a file: {}", path.display()));
    }
    if advertised_size != 0 && metadata.len() != advertised_size {
        return Err(crate::zerr!(
            "local blob {} size {} does not match manifest size {advertised_size}",
            path.display(),
            metadata.len()
        ));
    }
    Ok(())
}

fn short_digest(digest: &str) -> String {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    let keep = hex.len().min(12);
    format!("sha256:{keep}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::commit::commit_image;
    use sha2::{Digest as ShaDigest, Sha256};
    use std::io::{BufRead, BufReader, Read};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc::{channel, Sender};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn test_store() -> ImageStore {
        let dir = std::env::temp_dir().join(format!(
            "zerun-push-store-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        ImageStore::at(&dir).unwrap()
    }

    #[test]
    fn missing_local_image_fails_without_network() {
        let store = test_store();
        let mut client = RegistryClient::new();
        let reference = Reference::parse("localhost:1/org/app:v1").unwrap();
        let err = push_image(&store, &mut client, &reference).unwrap_err();
        assert!(err.to_string().contains("No such image"));
    }

    #[test]
    fn digest_references_are_rejected() {
        let store = test_store();
        let mut client = RegistryClient::new();
        let digest = format!("sha256:{}", "a".repeat(64));
        let reference = Reference::parse(&format!("localhost:1/org/app@{digest}")).unwrap();
        let err = push_image(&store, &mut client, &reference).unwrap_err();
        assert!(err.to_string().contains("not a digest reference"));
    }

    #[test]
    fn pushes_schema2_image_through_local_registry() {
        let store = test_store();
        let source = std::env::temp_dir().join(format!(
            "zerun-push-rootfs-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&source).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (done_tx, done_rx) = channel();
        let server = std::thread::spawn(move || serve_registry(listener, done_tx));

        let target = format!("localhost:{port}/org/app:v1");
        commit_image(&store, &source, &target, Default::default()).unwrap();
        let reference = Reference::parse(&target).unwrap();
        let mut client = RegistryClient::new();
        let result = push_image(&store, &mut client, &reference).unwrap();
        assert!(result.digest.starts_with("sha256:"));
        server.join().unwrap();
        done_rx.recv().unwrap();
        let _ = std::fs::remove_dir_all(&source);
    }

    fn create_multi_arch_record(
        store: &ImageStore,
        port: u16,
    ) -> (
        std::path::PathBuf,
        std::path::PathBuf,
        String,
        String,
        String,
    ) {
        let amd_root = std::env::temp_dir().join(format!(
            "zerun-push-multi-amd-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let arm_root = std::env::temp_dir().join(format!(
            "zerun-push-multi-arm-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&amd_root).unwrap();
        std::fs::create_dir_all(&arm_root).unwrap();
        std::fs::write(amd_root.join("marker"), b"amd64").unwrap();
        std::fs::write(arm_root.join("marker"), b"arm64").unwrap();
        let amd_target = format!("localhost:{port}/org/amd:v1");
        let arm_target = format!("localhost:{port}/org/arm:v1");
        let amd = commit_image(store, &amd_root, &amd_target, Default::default()).unwrap();
        let arm = commit_image(store, &arm_root, &arm_target, Default::default()).unwrap();
        let child = |record: &crate::image::store::ImageRecord, architecture: &str| {
            let bytes = store.read_blob(&record.manifest).unwrap().unwrap();
            serde_json::json!({
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "digest": record.manifest,
                "size": bytes.len(),
                "platform": {"os": "linux", "architecture": architecture},
            })
        };
        let index_bytes = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
            "manifests": [child(&amd, "amd64"), child(&arm, "arm64")],
        }))
        .unwrap();
        let index_digest = format!("sha256:{}", crate::image::store::sha256_hex(&index_bytes));
        store.write_blob(&index_digest, &index_bytes).unwrap();
        store
            .add_index_image(
                &format!("localhost:{port}/org/app"),
                Some("v1"),
                &arm.manifest,
                &arm.config,
                arm.size_bytes,
                Some(&index_digest),
            )
            .unwrap();
        (amd_root, arm_root, index_digest, amd.manifest, arm.manifest)
    }

    #[test]
    fn pushes_multi_arch_index_and_all_children() {
        let store = test_store();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (done_tx, done_rx) = channel();
        let server = std::thread::spawn(move || serve_registry(listener, done_tx));
        let (amd_root, arm_root, index_digest, amd_manifest, arm_manifest) =
            create_multi_arch_record(&store, port);

        let reference = Reference::parse(&format!("localhost:{port}/org/app:v1")).unwrap();
        let mut client = RegistryClient::new();
        let result = push_image(&store, &mut client, &reference).unwrap();
        assert_eq!(result.digest, index_digest);
        server.join().unwrap();
        done_rx.recv().unwrap();

        let _ = std::fs::remove_dir_all(&amd_root);
        let _ = std::fs::remove_dir_all(&arm_root);
        assert_ne!(index_digest, amd_manifest);
        assert_ne!(index_digest, arm_manifest);
    }

    #[test]
    fn rejects_incomplete_multi_arch_index_before_network() {
        let store = test_store();
        let child = "sha256:".to_string() + &"3".repeat(64);
        let index_bytes = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
            "manifests": [{"mediaType": "application/vnd.docker.distribution.manifest.v2+json", "digest": child, "size": 0}],
        }))
        .unwrap();
        let index_digest = format!("sha256:{}", crate::image::store::sha256_hex(&index_bytes));
        store.write_blob(&index_digest, &index_bytes).unwrap();
        let record_manifest = "sha256:".to_string() + &"4".repeat(64);
        let record_config = "sha256:".to_string() + &"5".repeat(64);
        store
            .add_index_image(
                "localhost:1/org/app",
                Some("v1"),
                &record_manifest,
                &record_config,
                1,
                Some(&index_digest),
            )
            .unwrap();

        let mut client = RegistryClient::new();
        let reference = Reference::parse("localhost:1/org/app:v1").unwrap();
        let err = push_image(&store, &mut client, &reference).unwrap_err();
        assert!(err.to_string().contains("child manifest blob is missing"));
    }

    /// A tiny stateless OCI registry protocol double. It rejects HEADs, starts
    /// all upload sessions, accepts monolithic upload PUTs, and accepts a
    /// manifest PUT with the correct content digest header.
    fn serve_registry(listener: TcpListener, done: Sender<()>) {
        use std::io::Write;
        for stream in listener.incoming().take(16) {
            let mut reader = BufReader::new(stream.unwrap());
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
                break;
            }
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                if let Some(value) = line
                    .to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(str::trim)
                {
                    content_length = value.parse().unwrap_or(0);
                }
            }
            if request_line.starts_with("PUT ") && request_line.contains("/manifests/") {
                let mut body = vec![0_u8; content_length];
                reader.read_exact(&mut body).unwrap();
                let mut hasher = Sha256::new();
                hasher.update(&body);
                let digest = format!("sha256:{:x}", hasher.finalize());
                let mut stream = reader.into_inner();
                let response = format!("HTTP/1.1 201 Created\r\nDocker-Content-Digest: {digest}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                stream.write_all(response.as_bytes()).unwrap();
                if request_line.contains("/manifests/v1") {
                    let _ = done.send(());
                    break;
                }
            } else if request_line.starts_with("PUT ") && request_line.contains("/blobs/uploads/") {
                let mut body = vec![0_u8; content_length];
                reader.read_exact(&mut body).unwrap();
                let mut stream = reader.into_inner();
                stream
                    .write_all(
                        b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .unwrap();
            } else if request_line.starts_with("GET ") && request_line.contains("/v2/") {
                let mut stream = reader.into_inner();
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .unwrap();
            } else if request_line.starts_with("POST ") {
                let mut stream = reader.into_inner();
                stream
                    .write_all(b"HTTP/1.1 202 Accepted\r\nLocation: /v2/org/app/blobs/uploads/test-session\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .unwrap();
            } else {
                let mut stream = reader.into_inner();
                stream
                    .write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .unwrap();
            }
        }
    }

    #[test]
    fn commit_and_push_helpers_validate_the_local_record() {
        let store = test_store();
        let source = std::env::temp_dir().join(format!(
            "zerun-commit-push-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&source).unwrap();
        let record = commit_image(
            &store,
            &source,
            "localhost:1/org/app:v1",
            Default::default(),
        )
        .unwrap();
        assert_ne!(record.manifest, record.config);
        let _ = std::fs::remove_dir_all(&source);
    }
}
