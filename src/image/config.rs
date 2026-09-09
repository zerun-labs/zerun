//! Parsed OCI image configuration (the JSON `config` blob referenced by a
//! manifest). Only the fields Zerun consumes are modeled; the rest of the
//! document is ignored.
use crate::error::ZResult;
use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ImageConfig {
    #[serde(default)]
    pub architecture: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub config: ConfigSection,
    #[serde(default)]
    pub rootfs: RootFs,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConfigSection {
    /// Image environment, each entry `KEY=VALUE` (order preserved).
    #[serde(default, rename = "Env")]
    pub env: Vec<String>,
    #[serde(default, rename = "Entrypoint")]
    pub entrypoint: Vec<String>,
    #[serde(default, rename = "Cmd")]
    pub cmd: Vec<String>,
    #[serde(default, rename = "WorkingDir")]
    pub working_dir: String,
    /// Image user (`USER` in a Dockerfile), e.g. "nginx" or "1000:1000".
    #[serde(default, rename = "User")]
    pub user: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RootFs {
    /// One `sha256:<hex>` per layer, in order: hashes of the *uncompressed*
    /// layer tars (OCI `diff_id`s).
    #[serde(default, rename = "diff_ids")]
    pub diff_ids: Vec<String>,
}

impl ImageConfig {
    pub fn parse(bytes: &[u8]) -> ZResult<Self> {
        serde_json::from_slice(bytes).map_err(|e| crate::zerr!("invalid image config json: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let cfg = ImageConfig::parse(
            br#"{
                "architecture": "amd64",
                "os": "linux",
                "config": {
                    "Env": ["PATH=/usr/local/sbin:/usr/bin:/bin"],
                    "WorkingDir": "/app",
                    "User": "nginx:nginx",
                    "Cmd": ["/bin/sh"]
                },
                "rootfs": {
                    "type": "layers",
                    "diff_ids": ["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
                }
            }"#,
        )
        .unwrap();
        assert_eq!(cfg.architecture, "amd64");
        assert_eq!(cfg.config.env.len(), 1);
        assert_eq!(cfg.config.working_dir, "/app");
        assert_eq!(cfg.config.user, "nginx:nginx");
        assert_eq!(cfg.config.cmd, vec!["/bin/sh"]);
        assert_eq!(cfg.rootfs.diff_ids.len(), 1);
    }

    #[test]
    fn empty_fields_default() {
        let cfg = ImageConfig::parse(b"{}").unwrap();
        assert!(cfg.config.env.is_empty());
        assert!(cfg.rootfs.diff_ids.is_empty());
        assert_eq!(cfg.os, "");
    }
}
