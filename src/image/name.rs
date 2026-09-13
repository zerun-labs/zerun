//! Image reference parsing (Docker-compatible subset).
//!
//! Grammar handled here:
//!   [registry/][namespace/]repository[:tag][@digest]
//!
//! Defaults: registry `docker.io`, tag `latest`. A single-component repository on
//! docker.io is interpreted as the `library` namespace (e.g. `alpine` ->
//! `docker.io/library/alpine`). Repository components, tags, registry ports, and
//! digest syntax are validated before they are used to construct registry URLs.
use crate::error::ZResult;

const DEFAULT_REGISTRY: &str = "docker.io";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub registry: String,
    /// Repository path without the registry, e.g. `library/alpine`.
    pub repository: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
}

impl Reference {
    /// Parse a user-supplied image reference.
    pub fn parse(input: &str) -> ZResult<Self> {
        let input = input.trim();
        if input.is_empty() {
            return Err(crate::zerr!("empty image reference"));
        }

        // Split off the digest first (@ is not valid in repo/tag names).
        let (rest, digest) = match input.rfind('@') {
            Some(pos) => {
                let d = &input[pos + 1..];
                if !is_digest(d) {
                    return Err(crate::zerr!("invalid digest in image reference: {d}"));
                }
                (&input[..pos], Some(d.to_ascii_lowercase()))
            }
            None => (input, None),
        };
        if rest.is_empty() {
            return Err(crate::zerr!("image reference has no repository: {input}"));
        }

        // Determine the registry: the first path component counts as a registry
        // when it looks like a host (contains '.' or ':' or is "localhost").
        let (registry, repo_part) = match rest.split_once('/') {
            Some((first, tail)) if looks_like_registry(first) => {
                (first.to_lowercase(), tail.to_string())
            }
            _ => (DEFAULT_REGISTRY.to_string(), rest.to_string()),
        };
        validate_registry(&registry)?;

        // Split tag from the repository tail (last ':' after the final '/').
        let (repo, tag) = split_tag(&repo_part)?;
        let repository = if registry == DEFAULT_REGISTRY && !repo.contains('/') {
            format!("library/{repo}")
        } else {
            repo
        };

        // Docker semantics: no tag means `latest`; a digest reference carries no
        // tag at all.
        let tag = if digest.is_some() {
            None
        } else {
            Some(tag.unwrap_or_else(|| "latest".to_string()))
        };

        Ok(Reference {
            registry,
            repository,
            tag,
            digest,
        })
    }

    /// Canonical string form, e.g. `docker.io/library/alpine:latest`.
    pub fn canonical(&self) -> String {
        let mut s = format!("{}/{}", self.registry, self.repository);
        if let Some(t) = &self.tag {
            s.push(':');
            s.push_str(t);
        }
        if let Some(d) = &self.digest {
            s.push('@');
            s.push_str(d);
        }
        s
    }
}

fn looks_like_registry(component: &str) -> bool {
    component == "localhost" || component.contains('.') || component.contains(':')
}

/// Split `repository[:tag]`, where ':' may only appear after the last '/'.
fn split_tag(repo_part: &str) -> ZResult<(String, Option<String>)> {
    let (repo, tag) = match repo_part.rfind(':') {
        Some(pos) if !repo_part[pos + 1..].contains('/') => {
            let repo = &repo_part[..pos];
            let tag = &repo_part[pos + 1..];
            if repo.is_empty() {
                return Err(crate::zerr!("image reference has empty repository"));
            }
            if tag.is_empty() {
                return Err(crate::zerr!("image reference has empty tag"));
            }
            (repo, Some(tag.to_ascii_lowercase()))
        }
        _ => (repo_part, None),
    };
    validate_repository(repo)?;
    if let Some(tag) = &tag {
        validate_tag(tag)?;
    }
    Ok((repo.to_ascii_lowercase(), tag))
}

fn validate_registry(registry: &str) -> ZResult<()> {
    if registry.is_empty()
        || registry
            .chars()
            .any(|c| c.is_ascii_control() || c.is_ascii_whitespace())
        || registry.contains(['/', '?', '#', '@', '\\'])
    {
        return Err(crate::zerr!(
            "invalid registry in image reference: {registry}"
        ));
    }

    if registry.starts_with('[') {
        let Some(close) = registry.find(']') else {
            return Err(crate::zerr!(
                "invalid registry in image reference: {registry}"
            ));
        };
        if close == 1
            || registry[close + 1..]
                .chars()
                .any(|c| c != ':' && !c.is_ascii_digit())
        {
            return Err(crate::zerr!(
                "invalid registry in image reference: {registry}"
            ));
        }
        if let Some(port) = registry.get(close + 1..).and_then(|s| s.strip_prefix(':')) {
            validate_port(port, registry)?;
        }
        return Ok(());
    }

    if registry.starts_with(':') || registry.matches(':').count() > 1 {
        return Err(crate::zerr!(
            "invalid registry in image reference: {registry}"
        ));
    }
    if let Some((host, port)) = registry.rsplit_once(':') {
        if host.is_empty() {
            return Err(crate::zerr!(
                "invalid registry in image reference: {registry}"
            ));
        }
        validate_port(port, registry)?;
    }
    Ok(())
}

fn validate_port(port: &str, registry: &str) -> ZResult<()> {
    let value = port
        .parse::<u16>()
        .map_err(|_| crate::zerr!("invalid registry port in image reference: {registry}"))?;
    if value == 0 {
        return Err(crate::zerr!(
            "invalid registry port in image reference: {registry}"
        ));
    }
    Ok(())
}

fn validate_repository(repository: &str) -> ZResult<()> {
    if repository.is_empty() || repository.len() > 255 {
        return Err(crate::zerr!(
            "invalid repository in image reference: {repository}"
        ));
    }
    for component in repository.split('/') {
        if !valid_repository_component(component) {
            return Err(crate::zerr!(
                "invalid repository component in image reference: {component}"
            ));
        }
    }
    Ok(())
}

fn valid_repository_component(component: &str) -> bool {
    let bytes = component.as_bytes();
    if bytes.is_empty() || !is_repo_alphanumeric(bytes[0]) {
        return false;
    }
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len() && is_repo_alphanumeric(bytes[index]) {
            index += 1;
        }
        if index == bytes.len() {
            return true;
        }
        match bytes[index] {
            b'.' => index += 1,
            b'_' if bytes.get(index + 1) == Some(&b'_') => index += 2,
            b'_' => index += 1,
            b'-' => {
                while index < bytes.len() && bytes[index] == b'-' {
                    index += 1;
                }
            }
            _ => return false,
        }
        if index == bytes.len() || !is_repo_alphanumeric(bytes[index]) {
            return false;
        }
    }
    true
}

fn is_repo_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

fn validate_tag(tag: &str) -> ZResult<()> {
    let bytes = tag.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || !(bytes[0].is_ascii_alphanumeric() || bytes[0] == b'_')
        || !bytes[1..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    {
        return Err(crate::zerr!("invalid tag in image reference: {tag}"));
    }
    Ok(())
}

fn is_digest(d: &str) -> bool {
    // Support the sha256:hex form used by registries.
    let Some((algo, hex)) = d.split_once(':') else {
        return false;
    };
    if algo != "sha256" {
        return false;
    }
    hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Reference {
        Reference::parse(s).unwrap()
    }

    #[test]
    fn docker_hub_defaults() {
        let r = p("alpine");
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.tag.as_deref(), Some("latest"));
        assert_eq!(r.canonical(), "docker.io/library/alpine:latest");

        let r = p("alpine:3.20");
        assert_eq!(r.tag.as_deref(), Some("3.20"));

        let r = p("library/nginx");
        assert_eq!(r.repository, "library/nginx");
    }

    #[test]
    fn custom_registry() {
        let r = p("my.registry.example:5000/team/app:v1");
        assert_eq!(r.registry, "my.registry.example:5000");
        assert_eq!(r.repository, "team/app");
        assert_eq!(r.tag.as_deref(), Some("v1"));

        let r = p("ghcr.io/org/repo");
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "org/repo");

        let r = p("localhost:5000/foo");
        assert_eq!(r.registry, "localhost:5000");
    }

    #[test]
    fn digests() {
        let r =
            p("busybox@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(
            r.digest.as_deref(),
            Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(r.tag, None);
        assert!(Reference::parse("busybox@sha256:short").is_err());
    }

    #[test]
    fn invalid() {
        assert!(Reference::parse("").is_err());
        assert!(Reference::parse("repo:").is_err());
        assert!(Reference::parse(":tag").is_err());
        for input in [
            "registry/",
            "repo//name",
            "/repo",
            "repo/name?query",
            "repo/name tag",
            "repo:name!",
            "example.com:abc/repo",
            "example.com:65536/repo",
        ] {
            assert!(Reference::parse(input).is_err(), "accepted invalid {input}");
        }
    }

    #[test]
    fn validates_repository_components_and_tags() {
        assert!(Reference::parse("org/a__b-c:v1.2-rc_1").is_ok());
        for input in ["org/a..b", "org/a___b", "org/.hidden", "org/a-"] {
            assert!(Reference::parse(input).is_err(), "accepted invalid {input}");
        }
    }

    #[test]
    fn canonicalizes_digest_hex_case() {
        let r =
            p("busybox@sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(
            r.digest.as_deref(),
            Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }
}
