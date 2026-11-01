//! Namespaced kernel settings requested with `--sysctl`.
//!
//! Sysctls are a privileged kernel interface, so this module accepts only the
//! families that are scoped to a container namespace. The child applies them
//! after networking is assembled (so interface sysctls such as
//! `net.ipv4.conf.eth0.*` exist) and before `/proc/sys` is remounted read-only
//! for the workload.
use crate::error::ZResult;
use crate::namespace::NetMode;
use crate::state::{IpcMode, NamespaceMode, NamespaceModes};
use std::collections::BTreeMap;
use std::path::PathBuf;

const MAX_KEY_BYTES: usize = 256;
const MAX_VALUE_BYTES: usize = 1024;

/// Parse one Docker-style `--sysctl KEY=VALUE` argument.
pub fn parse(raw: &str) -> Result<(String, String), String> {
    let Some((key, value)) = raw.split_once('=') else {
        return Err(format!("invalid --sysctl '{raw}' (expected KEY=VALUE)"));
    };
    validate_key(key).map_err(|error| format!("invalid --sysctl '{raw}': {error}"))?;
    validate_family(key).map_err(|error| format!("invalid --sysctl '{raw}': {error}"))?;
    validate_value(value).map_err(|error| format!("invalid --sysctl '{raw}': {error}"))?;
    Ok((key.to_string(), value.to_string()))
}

/// Validate that every requested key targets a private namespace owned by this
/// container. Sharing the host network or IPC namespace would turn what looks
/// like a container-local setting into a host mutation.
pub fn validate_for_namespaces(
    values: &BTreeMap<String, String>,
    namespaces: NamespaceModes,
    net: NetMode,
) -> Result<(), String> {
    for (key, value) in values {
        validate_key(key).map_err(|error| format!("invalid --sysctl key '{key}': {error}"))?;
        validate_family(key).map_err(|error| format!("invalid --sysctl key '{key}': {error}"))?;
        validate_value(value)
            .map_err(|error| format!("invalid --sysctl value for '{key}': {error}"))?;
        if key.starts_with("net.") {
            if matches!(net, NetMode::Host) {
                return Err(format!(
                    "--sysctl {key} requires a private network namespace; remove --net host"
                ));
            }
        } else if is_ipc_sysctl(key) {
            if matches!(namespaces.ipc, IpcMode::Host) {
                return Err(format!(
                    "--sysctl {key} requires a private IPC namespace; remove --ipc host"
                ));
            }
        } else if key == "kernel.domainname" && matches!(namespaces.uts, NamespaceMode::Host) {
            return Err(format!(
                "--sysctl {key} requires a private UTS namespace; remove --uts host"
            ));
        }
    }
    Ok(())
}

/// Apply validated settings inside the container's namespaces.
pub fn apply(
    values: &BTreeMap<String, String>,
    namespaces: NamespaceModes,
    net: NetMode,
) -> ZResult<()> {
    validate_for_namespaces(values, namespaces, net).map_err(|error| crate::zerr!("{error}"))?;
    for (key, value) in values {
        let path = proc_path(key);
        std::fs::write(&path, value.as_bytes())
            .map_err(|error| crate::zerr!("--sysctl {key}: write {}: {error}", path.display()))?;
    }
    Ok(())
}

fn validate_key(key: &str) -> Result<(), String> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        return Err(format!("key must contain 1-{MAX_KEY_BYTES} bytes"));
    }
    if !key.contains('.') {
        return Err("key must contain at least two dot-separated components".to_string());
    }
    if key.split('.').any(|component| {
        component.is_empty()
            || !component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    }) {
        return Err(
            "key components may contain only ASCII letters, digits, '_' or '-'".to_string(),
        );
    }
    Ok(())
}

fn validate_value(value: &str) -> Result<(), String> {
    if value.len() > MAX_VALUE_BYTES {
        return Err(format!("value exceeds {MAX_VALUE_BYTES} bytes"));
    }
    if value.chars().any(char::is_control) {
        return Err("value must not contain control characters".to_string());
    }
    Ok(())
}

fn validate_family(key: &str) -> Result<(), String> {
    if key.starts_with("net.") || is_ipc_sysctl(key) || key == "kernel.domainname" {
        Ok(())
    } else {
        Err(format!(
            "'{key}' is not allowed (supported: net.*, kernel.shm*, kernel.msg*, kernel.sem*, fs.mqueue.*, kernel.domainname)"
        ))
    }
}

fn is_ipc_sysctl(key: &str) -> bool {
    key.starts_with("fs.mqueue.")
        || key.starts_with("kernel.shm")
        || key.starts_with("kernel.msg")
        || key.starts_with("kernel.sem")
}

fn proc_path(key: &str) -> PathBuf {
    let mut path = PathBuf::from("/proc/sys");
    for component in key.split('.') {
        path.push(component);
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(items: &[(&str, &str)]) -> BTreeMap<String, String> {
        items
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn parses_namespaced_assignments_and_rejects_unsafe_syntax() {
        assert_eq!(
            parse("net.ipv4.ip_forward=1").unwrap(),
            ("net.ipv4.ip_forward".to_string(), "1".to_string())
        );
        assert_eq!(
            parse("kernel.sem=250 32000 32 128").unwrap().1,
            "250 32000 32 128"
        );
        assert!(parse("net.ipv4.ip_forward").is_err());
        assert!(parse("=1").is_err());
        assert!(parse("net..ip_forward=1").is_err());
        assert!(parse("net/ipv4/ip_forward=1").is_err());
        assert!(parse("net.ipv4.ip_forward=1\n2").is_err());
        assert!(parse("vm.swappiness=1").is_err());
        assert!(parse("kernel.hostname=container").is_err());
    }

    #[test]
    fn only_namespaced_families_are_allowed() {
        let private = NamespaceModes::default();
        let ok = values(&[
            ("net.ipv4.ip_forward", "1"),
            ("kernel.shmmax", "65536"),
            ("kernel.msgmax", "65536"),
            ("kernel.sem", "250 32000 32 128"),
            ("fs.mqueue.msg_max", "10"),
            ("kernel.domainname", "example.test"),
        ]);
        validate_for_namespaces(&ok, private, NetMode::None).unwrap();

        for key in ["vm.swappiness", "kernel.core_pattern", "kernel.hostname"] {
            let rejected = values(&[(key, "1")]);
            assert!(validate_for_namespaces(&rejected, private, NetMode::None).is_err());
        }
    }

    #[test]
    fn host_namespace_sharing_rejects_matching_families() {
        let net = values(&[("net.ipv4.ip_forward", "1")]);
        assert!(validate_for_namespaces(&net, NamespaceModes::default(), NetMode::Host).is_err());
        assert!(validate_for_namespaces(&net, NamespaceModes::default(), NetMode::Bridge).is_ok());

        let ipc = values(&[("kernel.shmmax", "65536")]);
        let host_ipc = NamespaceModes {
            ipc: IpcMode::Host,
            ..NamespaceModes::default()
        };
        assert!(validate_for_namespaces(&ipc, host_ipc, NetMode::None).is_err());
        assert!(validate_for_namespaces(&ipc, NamespaceModes::default(), NetMode::None).is_ok());

        let uts = values(&[("kernel.domainname", "example.test")]);
        let host_uts = NamespaceModes {
            uts: NamespaceMode::Host,
            ..NamespaceModes::default()
        };
        assert!(validate_for_namespaces(&uts, host_uts, NetMode::None).is_err());
    }
}
