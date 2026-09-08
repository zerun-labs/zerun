//! OCI / Docker v2 manifest and manifest-list (index) parsing, plus the
//! platform model used to select a single-architecture image.
use crate::error::ZResult;
use serde::Deserialize;

/// Accept header for manifest requests: modern schema2 manifests/indexes only
/// (Docker Hub and OCI registries serve these when offered; schema1 is
/// intentionally not requested).
pub const ACCEPT_MANIFEST: &str = concat!(
    "application/vnd.docker.distribution.manifest.v2+json, ",
    "application/vnd.docker.distribution.manifest.list.v2+json, ",
    "application/vnd.oci.image.manifest.v1+json, ",
    "application/vnd.oci.image.index.v1+json"
);

/// A content reference inside a manifest (config or layer).
#[derive(Debug, Clone, Deserialize)]
pub struct Descriptor {
    #[serde(default, rename = "mediaType")]
    pub media_type: String,
    pub digest: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub platform: Option<Platform>,
}

/// Single-architecture image manifest (schema2 / OCI).
#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    pub config: Descriptor,
    #[serde(default)]
    pub layers: Vec<Descriptor>,
}

/// Multi-architecture manifest list / OCI index.
#[derive(Debug, Clone, Deserialize)]
pub struct Index {
    #[serde(default)]
    pub manifests: Vec<Descriptor>,
}

/// A registry platform triple (`linux/amd64`, `linux/arm/v7`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct Platform {
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub architecture: String,
    #[serde(default)]
    pub variant: Option<String>,
}

impl Platform {
    pub fn parse(spec: &str) -> ZResult<Self> {
        let parts: Vec<&str> = spec.split('/').collect();
        match parts.as_slice() {
            [os, arch] => Ok(Platform {
                os: os.to_string(),
                architecture: arch.to_string(),
                variant: None,
            }),
            [os, arch, variant] => Ok(Platform {
                os: os.to_string(),
                architecture: arch.to_string(),
                variant: Some(variant.to_string()),
            }),
            _ => Err(crate::zerr!(
                "invalid platform '{spec}' (expected os/arch[/variant], e.g. linux/amd64)"
            )),
        }
    }

    fn matches(&self, want: &Platform) -> bool {
        if self.os != want.os || self.architecture != want.architecture {
            return false;
        }
        match (&want.variant, &self.variant) {
            (None, _) => true, // no requested variant: any is fine
            (Some(w), Some(v)) => w == v,
            (Some(_), None) => false,
        }
    }
}

/// The platform of this binary, in registry naming (`x86_64` -> `amd64`, ...).
pub fn host_platform() -> Platform {
    let (architecture, variant) = match std::env::consts::ARCH {
        "x86_64" => ("amd64", None),
        "aarch64" => ("arm64", None),
        "arm" => ("arm", arm_variant()),
        "riscv64" => ("riscv64", None),
        "powerpc64" => ("ppc64le", None),
        other => (other, None),
    };
    Platform {
        os: "linux".to_string(),
        architecture: architecture.to_string(),
        variant,
    }
}

/// Best-effort ARM variant from the kernel's machine string (`armv7l` -> v7).
fn arm_variant() -> Option<String> {
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return None;
    }
    let machine = unsafe { std::ffi::CStr::from_ptr(u.machine.as_ptr()) }
        .to_string_lossy()
        .to_string();
    let v = machine
        .strip_prefix("armv")
        .and_then(|rest| rest.chars().next())
        .filter(|c| c.is_ascii_digit())
        .map(|c| format!("v{c}"));
    v
}

/// Distinguish a single manifest from a multi-arch index by shape.
pub fn classify(bytes: &[u8]) -> ZResult<ImageDoc> {
    let v: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| crate::zerr!("invalid manifest json: {e}"))?;
    if let Some(manifests) = v.get("manifests").and_then(|m| m.as_array()) {
        if !manifests.is_empty() {
            let index: Index = serde_json::from_value(v)
                .map_err(|e| crate::zerr!("invalid image index json: {e}"))?;
            return Ok(ImageDoc::Index(index));
        }
    }
    let manifest: Manifest =
        serde_json::from_value(v).map_err(|e| crate::zerr!("invalid image manifest json: {e}"))?;
    if manifest.config.digest.is_empty() {
        return Err(crate::zerr!(
            "unsupported manifest (missing config digest; legacy schema1 is not supported)"
        ));
    }
    Ok(ImageDoc::Manifest(manifest))
}

/// A single manifest or a multi-arch index.
#[derive(Debug, Clone)]
pub enum ImageDoc {
    Manifest(Manifest),
    Index(Index),
}

impl ImageDoc {
    /// If this is an index, pick the descriptor for `want`; if it is already a
    /// single manifest, return `None` (no further resolution needed).
    pub fn select(&self, want: &Platform) -> ZResult<Option<&Descriptor>> {
        match self {
            ImageDoc::Manifest(_) => Ok(None),
            ImageDoc::Index(index) => {
                let matches: Vec<&Descriptor> = index
                    .manifests
                    .iter()
                    .filter(|d| {
                        d.platform
                            .as_ref()
                            .map(|p| p.matches(want))
                            .unwrap_or(false)
                    })
                    .collect();
                if matches.is_empty() {
                    let available: Vec<String> = index
                        .manifests
                        .iter()
                        .filter_map(|d| {
                            let p = d.platform.as_ref()?;
                            Some(format!(
                                "{}/{}",
                                p.os,
                                match &p.variant {
                                    Some(v) => format!("{}/{}", p.architecture, v),
                                    None => p.architecture.clone(),
                                }
                            ))
                        })
                        .collect();
                    return Err(crate::zerr!(
                        "image has no manifest for {}/{} (available: {})",
                        want.os,
                        want.architecture,
                        available.join(", ")
                    ));
                }
                // Prefer an exact variant match when one is requested.
                Ok(matches.into_iter().next())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"{
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 702,
            "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        },
        "layers": [{
            "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
            "size": 2800000,
            "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
        }]
    }"#;

    const INDEX: &str = r#"{
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
        "manifests": [
            {
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "size": 424,
                "digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
                "platform": {"architecture": "amd64", "os": "linux"}
            },
            {
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "size": 424,
                "digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
                "platform": {"architecture": "arm64", "os": "linux"}
            }
        ]
    }"#;

    #[test]
    fn classifies_single_and_index() {
        assert!(matches!(
            classify(MANIFEST.as_bytes()).unwrap(),
            ImageDoc::Manifest(_)
        ));
        assert!(matches!(
            classify(INDEX.as_bytes()).unwrap(),
            ImageDoc::Index(_)
        ));
    }

    #[test]
    fn selects_matching_platform() {
        let doc = classify(INDEX.as_bytes()).unwrap();
        let want = Platform {
            os: "linux".into(),
            architecture: "arm64".into(),
            variant: None,
        };
        let d = doc.select(&want).unwrap().unwrap();
        assert_eq!(
            d.digest,
            "sha256:4444444444444444444444444444444444444444444444444444444444444444"
        );
    }

    #[test]
    fn missing_platform_is_an_error() {
        let doc = classify(INDEX.as_bytes()).unwrap();
        let want = Platform {
            os: "linux".into(),
            architecture: "s390x".into(),
            variant: None,
        };
        assert!(doc.select(&want).is_err());
    }

    #[test]
    fn platform_matching_respects_variant() {
        let p = Platform {
            os: "linux".into(),
            architecture: "arm".into(),
            variant: Some("v7".into()),
        };
        let want_none = Platform {
            os: "linux".into(),
            architecture: "arm".into(),
            variant: None,
        };
        assert!(p.matches(&want_none));
        let want_v6 = Platform {
            os: "linux".into(),
            architecture: "arm".into(),
            variant: Some("v6".into()),
        };
        assert!(!p.matches(&want_v6));
    }
}
