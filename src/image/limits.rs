//! Bounds for image metadata read into memory.
//!
//! Registry responses and OCI archives are untrusted inputs. Layer content is
//! streamed to disk, but manifests, image configs, token responses, and layout
//! documents must be parsed as complete JSON documents. Keep those small enough
//! that a malicious endpoint cannot exhaust the runtime's address space.
use crate::error::ZResult;
use std::io::Read;

/// OCI/Docker manifest or multi-architecture index.
pub(crate) const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
/// OCI image configuration, including history and environment metadata.
pub(crate) const MAX_CONFIG_BYTES: usize = 8 * 1024 * 1024;
/// Registry token endpoint response.
pub(crate) const MAX_TOKEN_RESPONSE_BYTES: usize = 1024 * 1024;
/// OCI `index.json` in an image-layout archive.
pub(crate) const MAX_ARCHIVE_INDEX_BYTES: usize = 8 * 1024 * 1024;
/// OCI `oci-layout` marker document.
pub(crate) const MAX_LAYOUT_DOCUMENT_BYTES: usize = 64 * 1024;
/// Registry error body retained for a diagnostic snippet.
pub(crate) const MAX_ERROR_BODY_BYTES: usize = 8 * 1024;

/// Read one metadata document while enforcing an inclusive byte limit.
pub(crate) fn read_limited<R: Read>(
    reader: R,
    limit: usize,
    description: &str,
) -> ZResult<Vec<u8>> {
    let mut bytes = Vec::with_capacity(limit.min(16 * 1024));
    let read_limit = u64::try_from(limit).unwrap_or(u64::MAX);
    reader
        .take(read_limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| crate::zerr!("read {description}: {e}"))?;
    if bytes.len() > limit {
        return Err(crate::zerr!(
            "{description} exceeds the {limit}-byte metadata limit"
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_reader_enforces_inclusive_bound() {
        assert_eq!(read_limited(&b"abcd"[..], 4, "fixture").unwrap(), b"abcd");
        let error = read_limited(&b"abcde"[..], 4, "fixture").unwrap_err();
        assert!(error
            .to_string()
            .contains("exceeds the 4-byte metadata limit"));
        let error = read_limited(std::io::repeat(b'x'), 4, "stream").unwrap_err();
        assert!(error
            .to_string()
            .contains("stream exceeds the 4-byte metadata limit"));
    }
}
