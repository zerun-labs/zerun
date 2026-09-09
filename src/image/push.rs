//! OCI distribution push.
//!
//! Zerun stores images as schema2 manifests in a local blob store. Pushing is
//! therefore a normal OCI distribution transaction: check each referenced
//! blob, start a blob upload when the registry does not already have it, and
//! finally put the manifest under the requested tag. Layer files are streamed
//! from disk; they are never buffered wholly in memory.
use crate::error::ZResult;
use crate::image::manifest::{self, ImageDoc};
use crate::image::name::Reference;
use crate::image::registry::RegistryClient;
use crate::image::store::ImageStore;
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
    let manifest_bytes = store
        .read_blob(&record.manifest)?
        .ok_or_else(|| crate::zerr!("image manifest blob is missing: {}", record.manifest))?;
    let manifest_digest = format!(
        "sha256:{}",
        crate::image::store::sha256_hex(&manifest_bytes)
    );
    if manifest_digest != record.manifest {
        return Err(crate::zerr!(
            "local image manifest digest mismatch (record {}, content {manifest_digest})",
            record.manifest
        ));
    }

    // A multi-arch index would require pushing every referenced manifest and
    // its blobs. The current local image engine creates and stores single
    // manifests; reject indexes with a clear message rather than silently
    // pushing an incomplete image.
    let manifest = match manifest::classify(&manifest_bytes)? {
        ImageDoc::Manifest(m) => m,
        ImageDoc::Index(_) => {
            return Err(crate::zerr!(
                "pushing a multi-architecture image index is not supported yet"
            ))
        }
    };

    // Validate that the manifest is self-contained before touching the network.
    let mut descriptors = vec![manifest.config.clone()];
    descriptors.extend(manifest.layers.iter().cloned());
    for descriptor in &descriptors {
        let path = store.blob_path(&descriptor.digest)?;
        verify_blob(&path, descriptor.size)?;
    }

    // A local dev registry may be HTTPS-incompatible. Probe localhost endpoints
    // once and push everything to the selected scheme. Remote registries only
    // use their single HTTPS endpoint.
    let base = select_endpoint(client, reference)?;
    push_to(store, client, &base, reference, &manifest, &manifest_bytes)?;
    Ok(PushedImage {
        digest: manifest_digest,
    })
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

/// Push all blobs and the manifest to one API base URL.
fn push_to(
    store: &ImageStore,
    client: &mut RegistryClient,
    base: &str,
    reference: &Reference,
    manifest: &manifest::Manifest,
    manifest_bytes: &[u8],
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

    let manifest_url = format!("{base}/v2/{repo}/manifests/{}", tag_of(reference)?);
    let media_type = serde_json::from_slice::<serde_json::Value>(manifest_bytes)
        .ok()
        .and_then(|v| {
            v.get("mediaType")
                .and_then(|m| m.as_str())
                .map(str::to_string)
        })
        .filter(|m| {
            m.contains("docker.distribution.manifest.v2+json")
                || m.contains("oci.image.manifest.v1+json")
        })
        .ok_or_else(|| crate::zerr!("unsupported manifest mediaType for push"))?;
    let response =
        client.put_manifest(&manifest_url, registry, repo, &media_type, manifest_bytes)?;
    if let Some(returned) = response.header("docker-content-digest") {
        let expected = format!("sha256:{}", crate::image::store::sha256_hex(manifest_bytes));
        if returned != expected {
            return Err(crate::zerr!(
                "registry stored manifest {returned}, expected {expected}"
            ));
        }
    }
    Ok(())
}

fn tag_of(reference: &Reference) -> ZResult<&str> {
    reference
        .tag
        .as_deref()
        .ok_or_else(|| crate::zerr!("push reference has no tag"))
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
        let server = std::thread::spawn(move || serve_registry(listener));

        let target = format!("localhost:{port}/org/app:v1");
        commit_image(&store, &source, &target, Default::default()).unwrap();
        let reference = Reference::parse(&target).unwrap();
        let mut client = RegistryClient::new();
        let result = push_image(&store, &mut client, &reference).unwrap();
        assert!(result.digest.starts_with("sha256:"));
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&source);
    }

    /// A tiny stateless OCI registry protocol double. It rejects HEADs, starts
    /// all upload sessions, accepts monolithic upload PUTs, and accepts a
    /// manifest PUT with the correct content digest header.
    fn serve_registry(listener: TcpListener) {
        use std::io::Write;
        for stream in listener.incoming().take(8) {
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
