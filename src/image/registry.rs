//! OCI distribution (registry) client.
//!
//! Scope: anonymous `pull` only, which is all a daemonless run-only runtime
//! needs. It implements the Docker v2 token flow (WWW-Authenticate challenge ->
//! Bearer token), multi-arch manifest resolution, and Docker Hub mirror
//! inheritance (env `ZERUN_REGISTRY_MIRRORS`, then `/etc/docker/daemon.json`'s
//! `registry-mirrors`). Registry credentials (private registries) are out of
//! scope for now and produce a clear error.
use crate::error::ZResult;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const USER_AGENT: &str = concat!("zerun/", env!("CARGO_PKG_VERSION"));
const DOCKER_HUB_API: &str = "https://registry-1.docker.io";

pub struct RegistryClient {
    agent: ureq::Agent,
    /// Docker Hub mirror base URLs (with scheme, no trailing slash), in
    /// priority order. Only consulted for `docker.io` references.
    pub mirrors: Vec<String>,
    tokens: HashMap<String, CachedToken>,
}

#[derive(Clone)]
struct CachedToken {
    token: String,
    expires_at: u64,
}

#[derive(Debug)]
struct BearerChallenge {
    realm: String,
    service: String,
    scope: Option<String>,
}

impl RegistryClient {
    pub fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(30))
            .build();
        RegistryClient {
            agent,
            mirrors: discover_mirrors(),
            tokens: HashMap::new(),
        }
    }

    /// API endpoints for a registry, in priority order: configured mirrors for
    /// Docker Hub (a mirror is a caching proxy for the same repository paths),
    /// then the official endpoint.
    pub fn endpoints(&self, registry: &str) -> Vec<String> {
        if registry == "docker.io" {
            let mut v = self.mirrors.clone();
            v.push(DOCKER_HUB_API.to_string());
            v
        } else {
            vec![format!("https://{registry}")]
        }
    }

    /// Perform an authenticated GET. A 401 triggers the Bearer token flow once
    /// (refreshing a cached token is attempted twice at most), then the request
    /// is retried with the token. Non-2xx responses become errors with a body
    /// snippet.
    pub(crate) fn get(
        &mut self,
        url: &str,
        accept: Option<&str>,
        repo: &str,
    ) -> ZResult<ureq::Response> {
        let scope = format!("repository:{repo}:pull");
        for _ in 0..2 {
            let cached = self.tokens.get(&scope).cloned();
            let mut req = self.agent.get(url).set("User-Agent", USER_AGENT);
            if let Some(a) = accept {
                req = req.set("Accept", a);
            }
            if let Some(tok) = cached.as_ref() {
                if now() < tok.expires_at {
                    req = req.set("Authorization", &format!("Bearer {}", tok.token));
                }
            }
            match req.call() {
                Ok(resp) => return Ok(resp),
                Err(ureq::Error::Status(401, resp)) => {
                    let challenge = resp.header("www-authenticate").unwrap_or("").to_string();
                    self.tokens.remove(&scope);
                    let token = self.obtain_token(&challenge, repo)?;
                    self.tokens.insert(
                        scope.clone(),
                        CachedToken {
                            token,
                            expires_at: now() + 55,
                        },
                    );
                }
                Err(ureq::Error::Status(code, resp)) => {
                    let body = resp.into_string().unwrap_or_default();
                    let snippet: String = body.chars().take(300).collect();
                    return Err(crate::zerr!(
                        "registry request failed: {url}: HTTP {code}: {snippet}"
                    ));
                }
                Err(e) => {
                    return Err(crate::zerr!("registry request failed: {url}: {e}"));
                }
            }
        }
        Err(crate::zerr!(
            "registry request failed: {url}: authentication failed"
        ))
    }

    /// Bearer token dance against the realm from a `WWW-Authenticate` header.
    fn obtain_token(&self, challenge: &str, repo: &str) -> ZResult<String> {
        let ch = parse_bearer_challenge(challenge).ok_or_else(|| {
            crate::zerr!(
                "registry requires unsupported authentication: '{challenge}' \
                 (anonymous pull supports the standard Bearer token flow)"
            )
        })?;
        let scope = ch
            .scope
            .unwrap_or_else(|| format!("repository:{repo}:pull"));
        let mut url = ch.realm;
        url.push(if url.contains('?') { '&' } else { '?' });
        url.push_str("service=");
        url.push_str(&encode_query(&ch.service));
        url.push_str("&scope=");
        url.push_str(&encode_query(&scope));

        let resp = self
            .agent
            .get(&url)
            .set("User-Agent", USER_AGENT)
            .call()
            .map_err(|e| match e {
                ureq::Error::Status(code, r) => {
                    let body = r.into_string().unwrap_or_default();
                    crate::zerr!("token endpoint {url}: HTTP {code}: {body}")
                }
                other => crate::zerr!("token endpoint {url}: {other}"),
            })?;
        let body = resp
            .into_string()
            .map_err(|e| crate::zerr!("read token response: {e}"))?;
        let v: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| crate::zerr!("parse token response: {e}"))?;
        v.get("token")
            .or_else(|| v.get("access_token"))
            .and_then(|t| t.as_str())
            .map(str::to_string)
            .ok_or_else(|| crate::zerr!("token endpoint returned no token"))
    }
}

impl Default for RegistryClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse `Bearer realm="...",service="...",scope="..."` (quote-aware).
fn parse_bearer_challenge(h: &str) -> Option<BearerChallenge> {
    let rest = h.trim().strip_prefix("Bearer ")?;
    let mut fields = HashMap::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for c in rest.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                if let Some((k, v)) = split_kv(&cur) {
                    fields.insert(k, v);
                }
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    if let Some((k, v)) = split_kv(&cur) {
        fields.insert(k, v);
    }
    let realm = fields.get("realm")?.clone();
    Some(BearerChallenge {
        realm,
        service: fields.get("service").cloned().unwrap_or_default(),
        scope: fields.get("scope").cloned(),
    })
}

fn split_kv(s: &str) -> Option<(String, String)> {
    let (k, v) = s.split_once('=')?;
    Some((k.trim().to_string(), v.trim().trim_matches('"').to_string()))
}

/// Discover Docker Hub mirrors: env first, then `/etc/docker/daemon.json`.
fn discover_mirrors() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Ok(v) = std::env::var("ZERUN_REGISTRY_MIRRORS") {
        for m in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            out.push(normalize_mirror(m));
        }
    }
    if let Ok(text) = std::fs::read_to_string("/etc/docker/daemon.json") {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(list) = v.get("registry-mirrors").and_then(|m| m.as_array()) {
                for m in list.iter().filter_map(|m| m.as_str()) {
                    let m = normalize_mirror(m);
                    if !out.contains(&m) {
                        out.push(m);
                    }
                }
            }
        }
    }
    out
}

fn normalize_mirror(m: &str) -> String {
    let m = m.trim().trim_end_matches('/');
    if m.starts_with("http://") || m.starts_with("https://") {
        m.to_string()
    } else {
        format!("https://{m}")
    }
}

/// Percent-encode a query parameter value (spaces, ':', '/', ',' and friends).
fn encode_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bearer_challenge() {
        let ch = parse_bearer_challenge(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#,
        )
        .unwrap();
        assert_eq!(ch.realm, "https://auth.docker.io/token");
        assert_eq!(ch.service, "registry.docker.io");
        assert_eq!(ch.scope.as_deref(), Some("repository:library/alpine:pull"));
        assert!(parse_bearer_challenge("Basic realm=x").is_none());
    }

    #[test]
    fn query_encoding() {
        assert_eq!(
            encode_query("repository:library/alpine:pull"),
            "repository%3Alibrary%2Falpine%3Apull"
        );
        assert_eq!(encode_query("abc-_.~"), "abc-_.~");
    }

    #[test]
    fn endpoints_prefer_mirrors() {
        let mut c = RegistryClient::new();
        c.mirrors = vec!["https://mirror.example".to_string()];
        let eps = c.endpoints("docker.io");
        assert_eq!(eps[0], "https://mirror.example");
        assert_eq!(eps[1], "https://registry-1.docker.io");
        let eps2 = c.endpoints("ghcr.io");
        assert_eq!(eps2, vec!["https://ghcr.io"]);
    }

    #[test]
    fn mirror_normalization() {
        assert_eq!(
            normalize_mirror("docker.m.daocloud.io/"),
            "https://docker.m.daocloud.io"
        );
        assert_eq!(
            normalize_mirror("https://mirror.example/"),
            "https://mirror.example"
        );
    }
}
