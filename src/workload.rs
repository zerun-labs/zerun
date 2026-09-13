//! Workload process helpers shared by the direct-exec and mini-init paths.
//!
//! Containers built from OCI images run with an explicit environment
//! (`config.Env` + defaults + `-e` overrides). When that environment is set, the
//! process environment is cleared and replaced, so any bare argv[0] (for example
//! `nginx`) must be resolved against the container `PATH` before exec.
use crate::error::ZResult;

/// Container-conventional default PATH when an image config does not set one.
pub const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Validate an environment variable name before passing it to `Command`.
/// Empty names, `=` and NUL are rejected because they cannot represent a
/// portable `NAME=VALUE` entry and Rust cannot pass NUL through execve.
pub fn validate_env_key(key: &str) -> ZResult<()> {
    if key.is_empty() {
        return Err(crate::zerr!("environment variable name cannot be empty"));
    }
    if key.contains('=') {
        return Err(crate::zerr!("environment variable name cannot contain '='"));
    }
    if key.contains('\0') {
        return Err(crate::zerr!("environment variable name cannot contain NUL"));
    }
    Ok(())
}

/// Validate a complete `NAME=VALUE` pair.
pub fn validate_env_pair(key: &str, value: &str) -> ZResult<()> {
    validate_env_key(key)?;
    if value.contains('\0') {
        return Err(crate::zerr!("environment variable '{key}' contains NUL"));
    }
    Ok(())
}

/// Validate the CLI/state representation, which may be either `NAME=VALUE` or
/// a bare `NAME` requesting host-environment passthrough.
pub fn validate_env_spec(spec: &str) -> ZResult<()> {
    match spec.split_once('=') {
        Some((key, value)) => validate_env_pair(key, value),
        None => validate_env_key(spec),
    }
}

/// Look up the last value of `key` in an ordered env list.
pub fn env_value<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
    env.iter()
        .rev()
        .find_map(|(k, v)| if k == key { Some(v.as_str()) } else { None })
}

/// Resolve a bare argv[0] against the container `PATH`. Returns argv[0]
/// unchanged when it already contains `/` or cannot be found (exec then fails
/// naturally with a clear ENOENT error).
pub fn resolve_argv0(argv0: &str, env: &[(String, String)]) -> String {
    if argv0.contains('/') {
        return argv0.to_string();
    }
    let path = env_value(env, "PATH").unwrap_or(DEFAULT_PATH);
    for dir in path.split(':') {
        if dir.is_empty() {
            continue;
        }
        let cand = std::path::Path::new(dir).join(argv0);
        if cand.is_file() {
            return cand.to_string_lossy().into_owned();
        }
    }
    argv0.to_string()
}

/// Configure the environment of a `Command`:
/// - `Some(pairs)`: image mode — clear the inherited environment and set the
///   explicit container environment (caller guarantees PATH/HOME/HOSTNAME).
/// - `None`: legacy `--rootfs` mode — inherit the host environment and inject
///   the container-conventional defaults.
pub fn apply_env(
    cmd: &mut std::process::Command,
    env: Option<&[(String, String)]>,
    hostname: Option<&str>,
    id: &str,
) {
    match env {
        Some(pairs) => {
            cmd.env_clear();
            for (k, v) in pairs {
                cmd.env(k, v);
            }
        }
        None => {
            cmd.env("PATH", DEFAULT_PATH)
                .env("HOME", "/root")
                .env("HOSTNAME", hostname.unwrap_or(id));
        }
    }
}

/// Resolve a full argv for exec: when an explicit container environment is set,
/// bare argv[0] entries are resolved against the container PATH; otherwise the
/// list is returned unchanged (legacy mode keeps the previous execvp behavior).
pub fn resolve_argv(env: Option<&[(String, String)]>, argv: &[String]) -> Vec<String> {
    let Some(env) = env else {
        return argv.to_vec();
    };
    let mut out = argv.to_vec();
    if let Some(first) = out.first_mut() {
        *first = resolve_argv0(first, env);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_validation_rejects_execve_invalid_entries() {
        assert!(validate_env_pair("A", "ok").is_ok());
        assert!(validate_env_spec("A").is_ok());
        assert!(validate_env_spec("A=").is_ok());
        assert!(validate_env_spec("=value").is_err());
        assert!(validate_env_spec("A=B=C").is_ok());
        assert!(validate_env_pair("A", "bad\0value").is_err());
        assert!(validate_env_key("A=B").is_err());
    }
}
