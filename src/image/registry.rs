//! OCI distribution (registry) client.
//!
//! Scope: authenticated OCI `pull`, `login`, and `logout`. It implements the
//! Docker v2 token flow (WWW-Authenticate challenge -> Bearer token), Basic
//! challenges, multi-arch manifest resolution with transient retries, and Docker Hub mirror
//! inheritance. Mirror priority: env `ZERUN_REGISTRY_MIRRORS`, then the zerun
//! config file (`/etc/zerun/config.toml`, or `ZERUN_CONFIG` / user config;
//! `[registry] mirrors = [...]`), then `/etc/docker/daemon.json`'s
//! `registry-mirrors`. Credentials are read from the owner-only zerun store;
//! they are deliberately not sent to Docker Hub mirrors.
use crate::error::ZResult;
use crate::image::auth::{normalize_registry, Credential, CredentialStore};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::path::Path;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const USER_AGENT: &str = concat!("zerun/", env!("CARGO_PKG_VERSION"));
const DOCKER_HUB_API: &str = "https://registry-1.docker.io";

pub struct RegistryClient {
    agent: ureq::Agent,
    /// Docker Hub mirror base URLs (with scheme, no trailing slash), in
    /// priority order. Only consulted for `docker.io` references.
    pub mirrors: Vec<String>,
    credentials: BTreeMap<String, Credential>,
    tokens: HashMap<String, CachedToken>,
}

#[derive(Clone)]
struct CachedToken {
    /// Complete Authorization header value ("Basic ..." or "Bearer ...").
    authorization: String,
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
        Self::with_credentials(load_credentials())
    }

    pub(crate) fn with_credentials(credentials: BTreeMap<String, Credential>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(30))
            .build();
        RegistryClient {
            agent,
            mirrors: discover_mirrors(),
            credentials,
            tokens: HashMap::new(),
        }
    }

    /// API endpoints for a registry, in priority order: configured mirrors for
    /// Docker Hub (a mirror is a caching proxy for the same repository paths),
    /// then the official endpoint. Explicit localhost dev registries try plain
    /// HTTP first; remote registries are HTTPS-only.
    pub fn endpoints(&self, registry: &str) -> Vec<String> {
        if registry == "docker.io" {
            let mut v = self.mirrors.clone();
            v.push(DOCKER_HUB_API.to_string());
            v
        } else if registry == "localhost" || registry.starts_with("localhost:") {
            vec![format!("http://{registry}"), format!("https://{registry}")]
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
        registry: &str,
        repo: &str,
    ) -> ZResult<ureq::Response> {
        let headers: Vec<(&str, &str)> = accept.map(|a| vec![("Accept", a)]).unwrap_or_default();
        self.request(
            Method::Get,
            url,
            RequestOptions {
                registry,
                repo,
                scope: &format!("repository:{repo}:pull"),
                headers: &headers,
                body: RequestBody::None,
            },
        )
    }

    /// Perform an authenticated HEAD request. `404` is not an error because
    /// callers use HEAD for content-addressed blob existence checks.
    pub(crate) fn head(
        &mut self,
        url: &str,
        registry: &str,
        repo: &str,
    ) -> ZResult<Option<ureq::Response>> {
        match self.request(
            Method::Head,
            url,
            RequestOptions {
                registry,
                repo,
                scope: &format!("repository:{repo}:pull,push"),
                headers: &[],
                body: RequestBody::None,
            },
        ) {
            Ok(resp) => Ok(Some(resp)),
            Err(e) if e.0.contains("HTTP 404:") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Start a distribution blob-upload session. The registry may accept the
    /// whole blob on this request (HTTP 201), or return an upload location for
    /// a monolithic PUT.
    pub(crate) fn start_blob_upload(
        &mut self,
        base: &str,
        repo: &str,
        digest: &str,
    ) -> ZResult<Option<String>> {
        let url = format!("{base}/v2/{repo}/blobs/uploads/?digest={digest}");
        let resp = self.request(
            Method::Post,
            &url,
            RequestOptions {
                registry: registry_from_base(base)?,
                repo,
                scope: &format!("repository:{repo}:pull,push"),
                headers: &[],
                body: RequestBody::None,
            },
        )?;
        let status = resp.status();
        if status == 201 {
            return Ok(None);
        }
        if status != 202 {
            let body = response_snippet(resp);
            return Err(crate::zerr!(
                "start blob upload {digest}: HTTP {status}: {body}"
            ));
        }
        let location = resp.header("location").map(str::to_string);
        if location.is_none() {
            return Err(crate::zerr!(
                "registry accepted blob upload {digest} but returned no upload location"
            ));
        }
        Ok(location.map(|loc| absolute_url(base, &loc)))
    }

    /// Upload a small blob (config or manifest descriptor) as one request.
    pub(crate) fn put_blob_bytes(
        &mut self,
        url: &str,
        registry: &str,
        repo: &str,
        bytes: &[u8],
    ) -> ZResult<ureq::Response> {
        self.request(
            Method::Put,
            url,
            RequestOptions {
                registry,
                repo,
                scope: &format!("repository:{repo}:pull,push"),
                headers: &[],
                body: RequestBody::Bytes(bytes),
            },
        )
    }

    /// Upload a layer file as a streaming request (never materialized in RAM).
    pub(crate) fn put_blob_file(
        &mut self,
        url: &str,
        registry: &str,
        repo: &str,
        path: &Path,
    ) -> ZResult<ureq::Response> {
        let size = std::fs::metadata(path)
            .map_err(|e| crate::zerr!("stat blob {}: {e}", path.display()))?
            .len();
        self.request(
            Method::Put,
            url,
            RequestOptions {
                registry,
                repo,
                scope: &format!("repository:{repo}:pull,push"),
                headers: &[],
                body: RequestBody::File(path, size),
            },
        )
    }

    /// Put a signed manifest descriptor. `media_type` must be the exact
    /// manifest mediaType; registries reject a generic JSON content type.
    pub(crate) fn put_manifest(
        &mut self,
        url: &str,
        registry: &str,
        repo: &str,
        media_type: &str,
        bytes: &[u8],
    ) -> ZResult<ureq::Response> {
        let headers = [("Content-Type", media_type)];
        self.request(
            Method::Put,
            url,
            RequestOptions {
                registry,
                repo,
                scope: &format!("repository:{repo}:pull,push"),
                headers: &headers,
                body: RequestBody::Bytes(bytes),
            },
        )
    }

    /// Shared authenticated request path used by pull and push. A 401 starts
    /// (or refreshes) a Bearer token and retries once; transport failures and
    /// transient HTTP statuses are retried twice. Bodies supplied as files are
    /// reopened on every attempt, so streaming uploads remain retryable.
    fn request(
        &mut self,
        method: Method,
        url: &str,
        opts: RequestOptions<'_>,
    ) -> ZResult<ureq::Response> {
        let scope = opts.scope.to_string();
        for auth_round in 0..2 {
            let cached = self.tokens.get(&scope).cloned();
            for attempt in 0..3 {
                let mut req = self
                    .agent
                    .request(method.as_str(), url)
                    .set("User-Agent", USER_AGENT);
                if let Some(token) = cached.as_ref() {
                    if now() < token.expires_at {
                        req = req.set("Authorization", &token.authorization);
                    }
                }
                for (name, value) in opts.headers {
                    req = req.set(name, value);
                }
                if let RequestBody::File(_, size) = opts.body {
                    req = req.set("Content-Length", &size.to_string());
                }
                let result = match opts.body {
                    RequestBody::None => req.call(),
                    RequestBody::Bytes(bytes) => req.send_bytes(bytes),
                    RequestBody::File(path, _) => match File::open(path) {
                        Ok(file) => req.send(file),
                        Err(e) => {
                            return Err(crate::zerr!("open blob {}: {e}", path.display()));
                        }
                    },
                };
                match result {
                    Ok(resp) => return Ok(resp),
                    Err(ureq::Error::Status(401, resp)) => {
                        let challenge = resp.header("www-authenticate").unwrap_or("").to_string();
                        self.tokens.remove(&scope);
                        let credential = self.credential_for(opts.registry, url).cloned();
                        let authorization = self.authorization_for_challenge(
                            &challenge,
                            opts.repo,
                            opts.scope,
                            credential.as_ref(),
                        )?;
                        self.tokens.insert(
                            scope.clone(),
                            CachedToken {
                                authorization,
                                expires_at: now() + 55,
                            },
                        );
                        if auth_round == 0 {
                            break;
                        }
                        return Err(crate::zerr!(
                            "registry request failed: {url}: authentication failed; check \
                             'zerun login {}'",
                            opts.registry
                        ));
                    }
                    Err(ureq::Error::Status(code, resp)) => {
                        let retry_after = retry_after(&resp);
                        let body = response_snippet(resp);
                        let err =
                            crate::zerr!("registry request failed: {url}: HTTP {code}: {body}");
                        if is_retryable_status(code) && attempt < 2 {
                            thread::sleep(retry_delay(attempt, retry_after));
                            continue;
                        }
                        return Err(err);
                    }
                    Err(e) => {
                        let err = crate::zerr!("registry request failed: {url}: {e}");
                        if attempt < 2 {
                            thread::sleep(retry_delay(attempt, None));
                            continue;
                        }
                        return Err(err);
                    }
                }
            }
        }
        Err(crate::zerr!(
            "registry request failed: {url}: authentication failed; check 'zerun login {}'",
            opts.registry
        ))
    }

    /// Validate credentials against the registry's `/v2/` endpoint before they
    /// are written to disk. `get` handles both Basic and Bearer challenges.
    pub fn verify_login(&mut self, registry: &str, credential: &Credential) -> ZResult<()> {
        let registry = normalize_registry(registry)?;
        let mut probe =
            Self::with_credentials(BTreeMap::from([(registry.clone(), credential.clone())]));
        // The credential is keyed by docker.io, but its API endpoint is the
        // registry-1 hostname; the bare domain is not the API host.
        // Localhost registries may be plain HTTP, so try endpoint fallbacks.
        let hosts = probe.endpoints(&registry);
        let mut last_error = None;
        for host in hosts {
            match probe.get(&format!("{host}/v2/"), None, &registry, "") {
                Ok(_) => return Ok(()),
                Err(e) => last_error = Some(e),
            }
        }
        match last_error {
            Some(e) => Err(e),
            None => Err(crate::zerr!("no registry endpoint available")),
        }
    }

    fn credential_for(&self, registry: &str, url: &str) -> Option<&Credential> {
        if registry == "docker.io" {
            // Mirrors are often shared caching services; never leak Hub login
            // credentials to them.
            if url.starts_with(DOCKER_HUB_API) {
                return self.credentials.get(registry);
            }
            return None;
        }
        if url.starts_with(&format!("https://{registry}/"))
            || url.starts_with(&format!("http://{registry}/"))
        {
            self.credentials.get(registry)
        } else {
            None
        }
    }

    fn authorization_for_challenge(
        &self,
        challenge: &str,
        repo: &str,
        default_scope: &str,
        credential: Option<&Credential>,
    ) -> ZResult<String> {
        if challenge.trim().eq_ignore_ascii_case("basic")
            || challenge.trim_start().to_lowercase().starts_with("basic ")
        {
            let Some(credential) = credential else {
                return Err(crate::zerr!(
                    "registry requires Basic authentication; run 'zerun login <REGISTRY>'"
                ));
            };
            return Ok(credential.authorization());
        }
        let token = self.obtain_token(challenge, repo, default_scope, credential)?;
        Ok(format!("Bearer {token}"))
    }

    /// Bearer token dance against the realm from a `WWW-Authenticate` header.
    fn obtain_token(
        &self,
        challenge: &str,
        _repo: &str,
        default_scope: &str,
        credential: Option<&Credential>,
    ) -> ZResult<String> {
        let ch = parse_bearer_challenge(challenge).ok_or_else(|| {
            crate::zerr!(
                "registry requires unsupported authentication: '{challenge}' \
                 (standard Basic and Bearer token flows are supported)"
            )
        })?;
        let mut url = ch.realm;
        url.push(if url.contains('?') { '&' } else { '?' });
        url.push_str("service=");
        url.push_str(&encode_query(&ch.service));
        let scope = ch.scope.unwrap_or_default();
        if !scope.is_empty() {
            url.push_str("&scope=");
            url.push_str(&encode_query(&scope));
        } else if !default_scope.is_empty() {
            url.push_str("&scope=");
            url.push_str(&encode_query(default_scope));
        }

        let resp = (0..3)
            .find_map(|attempt| {
                let mut request = self.agent.get(&url).set("User-Agent", USER_AGENT);
                if let Some(credential) = credential {
                    request = request.set("Authorization", &credential.authorization());
                }
                match request.call() {
                    Ok(resp) => Some(Ok(resp)),
                    Err(ureq::Error::Status(code, resp)) => {
                        let retry_after = retry_after(&resp);
                        let body = resp.into_string().unwrap_or_default();
                        let err = crate::zerr!("token endpoint {url}: HTTP {code}: {body}");
                        if is_retryable_status(code) && attempt < 2 {
                            thread::sleep(retry_delay(attempt, retry_after));
                            None
                        } else {
                            Some(Err(err))
                        }
                    }
                    Err(other) => {
                        let err = crate::zerr!("token endpoint {url}: {other}");
                        if attempt < 2 {
                            thread::sleep(retry_delay(attempt, None));
                            None
                        } else {
                            Some(Err(err))
                        }
                    }
                }
            })
            .expect("retry loop always returns a final result")?;
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

/// HTTP methods supported by the registry request helper.
#[derive(Clone, Copy)]
enum Method {
    Get,
    Head,
    Post,
    Put,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
        }
    }
}

/// Description of one registry request, excluding authentication.
struct RequestOptions<'a> {
    registry: &'a str,
    repo: &'a str,
    /// Requested token scope. Registries commonly advertise a broader scope in
    /// their challenge; the cache is still keyed by what the caller asked for.
    scope: &'a str,
    headers: &'a [(&'a str, &'a str)],
    body: RequestBody<'a>,
}

/// Request bodies. Layer files stream directly from the content-addressed
/// store instead of being read into memory.
enum RequestBody<'a> {
    None,
    Bytes(&'a [u8]),
    File(&'a Path, u64),
}

/// Read a bounded response-body snippet for diagnostics. HEAD/204 responses
/// and unreadable bodies simply produce an empty string.
fn response_snippet(resp: ureq::Response) -> String {
    resp.into_string()
        .unwrap_or_default()
        .chars()
        .take(300)
        .collect()
}

/// Resolve a distribution `Location` header. OCI permits an absolute URL or a
/// path relative to the API base.
fn absolute_url(base: &str, location: &str) -> String {
    if location.starts_with("http://") || location.starts_with("https://") {
        location.to_string()
    } else if location.starts_with('/') {
        format!("{base}{location}")
    } else {
        format!("{base}/{location}")
    }
}

/// Derive the registry key used by the credential cache from an API base URL.
fn registry_from_base(base: &str) -> ZResult<&str> {
    let rest = base
        .strip_prefix("https://")
        .or_else(|| base.strip_prefix("http://"))
        .ok_or_else(|| crate::zerr!("registry API base must be HTTP(S): {base}"))?;
    let host = rest.split('/').next().unwrap_or_default();
    if host.is_empty() {
        return Err(crate::zerr!("registry API base has no host: {base}"));
    }
    let normalized = if host == "registry-1.docker.io" {
        "docker.io"
    } else {
        host
    };
    Ok(normalized)
}

impl Default for RegistryClient {
    fn default() -> Self {
        Self::new()
    }
}

fn load_credentials() -> BTreeMap<String, Credential> {
    match CredentialStore::open().and_then(|store| store.all()) {
        Ok(credentials) => credentials,
        Err(e) => {
            eprintln!("zerun: warning: ignoring registry credentials: {e}");
            BTreeMap::new()
        }
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

/// Discover Docker Hub mirrors in priority order:
/// 1. `ZERUN_REGISTRY_MIRRORS` (explicit per-invocation override);
/// 2. the zerun config file, user-level first, then `/etc/zerun/config.toml`;
/// 3. `/etc/docker/daemon.json` (`registry-mirrors`), for seamless Docker
///    migration on hosts that already run Docker.
fn discover_mirrors() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for m in env_mirrors() {
        push_unique(&mut out, m);
    }
    for path in config_file_candidates() {
        if let Ok(text) = std::fs::read_to_string(&path) {
            for m in mirrors_from_config_toml(&text) {
                push_unique(&mut out, normalize_mirror(&m));
            }
        }
    }
    if let Ok(text) = std::fs::read_to_string("/etc/docker/daemon.json") {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(list) = v.get("registry-mirrors").and_then(|m| m.as_array()) {
                for m in list.iter().filter_map(|m| m.as_str()) {
                    push_unique(&mut out, normalize_mirror(m));
                }
            }
        }
    }
    out
}

fn push_unique(out: &mut Vec<String>, mirror: String) {
    if !out.contains(&mirror) {
        out.push(mirror);
    }
}

fn env_mirrors() -> Vec<String> {
    std::env::var("ZERUN_REGISTRY_MIRRORS")
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(normalize_mirror)
                .collect()
        })
        .unwrap_or_default()
}

/// Config file locations, most specific first. `ZERUN_CONFIG` overrides the
/// search entirely (used by tests and by users who keep config elsewhere);
/// otherwise the per-user file shadows the system-wide one.
fn config_file_candidates() -> Vec<String> {
    if let Ok(p) = std::env::var("ZERUN_CONFIG") {
        if !p.is_empty() {
            return vec![p];
        }
    }
    let mut out = Vec::new();
    let user_cfg = std::env::var("XDG_CONFIG_HOME")
        .map(|xdg| format!("{xdg}/zerun/config.toml"))
        .or_else(|_| std::env::var("HOME").map(|home| format!("{home}/.config/zerun/config.toml")));
    if let Ok(p) = user_cfg {
        out.push(p);
    }
    out.push("/etc/zerun/config.toml".to_string());
    out
}

/// Parse `[registry] mirrors = [...]` from a zerun config file (TOML).
/// Unreadable/unsupported files simply contribute no mirrors.
fn mirrors_from_config_toml(text: &str) -> Vec<String> {
    #[derive(serde::Deserialize, Default)]
    struct FileConfig {
        #[serde(default)]
        registry: RegistrySection,
    }
    #[derive(serde::Deserialize, Default)]
    struct RegistrySection {
        #[serde(default)]
        mirrors: Vec<String>,
    }
    toml::from_str::<FileConfig>(text)
        .map(|c| c.registry.mirrors)
        .unwrap_or_default()
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

/// Transport failures and transient HTTP responses are worth one or two quick retries.
fn is_retryable_status(code: u16) -> bool {
    code == 408 || code == 429 || (500..600).contains(&code)
}

fn retry_after(resp: &ureq::Response) -> Option<Duration> {
    resp.header("retry-after")?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

fn retry_delay(attempt: usize, retry_after: Option<Duration>) -> Duration {
    let mut delay = Duration::from_millis(250 << attempt);
    if let Some(wait) = retry_after {
        delay = delay.max(wait.min(Duration::from_secs(5)));
    }
    delay.min(Duration::from_secs(5))
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
    fn retries_only_transient_http_statuses() {
        assert!(is_retryable_status(408));
        assert!(is_retryable_status(429));
        assert!(is_retryable_status(503));
        assert!(!is_retryable_status(401));
        assert!(!is_retryable_status(404));
        assert_eq!(retry_delay(0, None), Duration::from_millis(250));
        assert_eq!(retry_delay(1, None), Duration::from_millis(500));
        assert_eq!(
            retry_delay(0, Some(Duration::from_secs(30))),
            Duration::from_secs(5)
        );
    }

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

    #[test]
    fn config_toml_parses_mirrors() {
        let text = r#"
            # zerun config
            [registry]
            mirrors = ["https://mirror.a.example", "docker.m.daocloud.io"]
        "#;
        assert_eq!(
            mirrors_from_config_toml(text),
            vec![
                "https://mirror.a.example".to_string(),
                "docker.m.daocloud.io".to_string()
            ]
        );
        assert!(mirrors_from_config_toml("not toml [").is_empty());
        assert!(mirrors_from_config_toml("[other]\nx = 1").is_empty());
        assert!(mirrors_from_config_toml("").is_empty());
    }

    #[test]
    fn config_mirrors_are_normalized_and_deduped() {
        let text = "[registry]\nmirrors = [\"mirror.example/\", \"https://mirror.example\"]\n";
        let parsed = mirrors_from_config_toml(text);
        assert_eq!(parsed.len(), 2);
        let mut out = Vec::new();
        for m in parsed {
            push_unique(&mut out, normalize_mirror(&m));
        }
        assert_eq!(out, vec!["https://mirror.example".to_string()]);
    }
}
