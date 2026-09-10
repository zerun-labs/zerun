//! Docker-style selectors for the detached-container list.
//!
//! Repeated selectors are ANDed. A status selector may address non-running
//! records directly, matching Docker's behavior; other selectors merely
//! narrow whichever records the caller asked `zerun ps` to consider.

use crate::state::{ContainerState, Status};

/// Selection rules for `zerun ps --filter KEY=VALUE`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PsFilter {
    status: Option<Status>,
    name: Option<String>,
    id: Option<String>,
    image: Option<String>,
    exit_code: Option<i32>,
    net: Option<String>,
    labels: Vec<(String, Option<String>)>,
}

impl PsFilter {
    /// Set one `key=value` selector.
    pub fn set(&mut self, key: &str, value: &str) -> Result<(), String> {
        let invalid = |what: &str| Err(format!("invalid {what}: {value:?}"));
        match key {
            "status" => {
                let status = match value {
                    "created" => Status::Created,
                    "running" => Status::Running,
                    "exited" => Status::Exited,
                    _ => return invalid("status"),
                };
                self.status = Some(status);
                Ok(())
            }
            "name" | "id" | "image" | "net" => {
                if value.is_empty() {
                    return invalid(key);
                }
                match key {
                    "name" => self.name = Some(value.to_string()),
                    "id" => self.id = Some(value.to_string()),
                    "image" => self.image = Some(value.to_string()),
                    _ => self.net = Some(value.to_string()),
                }
                Ok(())
            }
            "exitCode" => match value.parse::<i32>() {
                Ok(code) => {
                    self.exit_code = Some(code);
                    Ok(())
                }
                Err(_) => invalid("exit code"),
            },
            "label" => {
                let (name, wanted) = match value.split_once('=') {
                    Some((name, value)) => (name, Some(value)),
                    None => (value, None),
                };
                if name.is_empty() {
                    return invalid("label");
                }
                self.labels
                    .push((name.to_string(), wanted.map(String::from)));
                Ok(())
            }
            _ => Err(format!("unknown ps filter {key:?}")),
        }
    }

    /// Whether the filter must see non-running records to be meaningful.
    pub fn widens_status(&self) -> bool {
        self.status.is_some_and(|status| status != Status::Running) || self.exit_code.is_some()
    }

    /// Whether a record satisfies every configured selector.
    pub fn matches(&self, state: &ContainerState) -> bool {
        let status_ok = self.status.is_none_or(|want| state.status == want);
        let id_ok = self
            .id
            .as_ref()
            .is_none_or(|want| state.id.starts_with(want.as_str()));
        let name_ok = self.name.as_ref().is_none_or(|want| {
            state
                .name
                .as_deref()
                .is_some_and(|name| name == want.as_str())
        });
        let image_ok = self.image.as_ref().is_none_or(|want| state.image == *want);
        let net_ok = self.net.as_ref().is_none_or(|want| state.net == *want);
        let exit_ok = self
            .exit_code
            .is_none_or(|want| state.exit_code == Some(want));
        let labels_ok = self.labels.iter().all(|(name, wanted)| {
            state
                .labels
                .get(name)
                .is_some_and(|found| wanted.as_ref().is_none_or(|value| found == value))
        });
        status_ok && id_ok && name_ok && image_ok && net_ok && exit_ok && labels_ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Status;
    use std::collections::BTreeMap;

    fn state(status: Status, exit_code: Option<i32>) -> ContainerState {
        ContainerState {
            version: 1,
            id: "0123456789ab".to_string(),
            name: Some("web".to_string()),
            image: "alpine:latest".to_string(),
            pid: None,
            status,
            exit_code,
            created: "2026-01-01T00:00:00Z".to_string(),
            started: None,
            finished: None,
            rootless: false,
            net: "none".to_string(),
            ports: vec![],
            port_protocols: None,
            port_ips: None,
            ip: None,
            cmd: vec!["sh".to_string()],
            env: vec![],
            cwd: None,
            user: None,
            capabilities: None,
            labels: BTreeMap::new(),
            log: String::new(),
            log_max_size: None,
            log_max_file: None,
            rootfs: String::new(),
            overlay: None,
            tmpfs_upper: false,
            launch_args: None,
            table: None,
            veth: None,
            cgroup: None,
            metrics: None,
        }
    }

    fn filter(key: &str, value: &str) -> PsFilter {
        let mut filter = PsFilter::default();
        filter.set(key, value).unwrap();
        filter
    }

    #[test]
    fn parses_status_and_exit_selectors() {
        assert!(filter("status", "running").matches(&state(Status::Running, None)));
        assert!(filter("status", "exited").matches(&state(Status::Exited, Some(0))));
        assert!(!filter("status", "running").matches(&state(Status::Exited, Some(0))));
        assert!(filter("exitCode", "7").matches(&state(Status::Exited, Some(7))));
        assert!(!filter("exitCode", "0").matches(&state(Status::Exited, Some(7))));
        assert!(PsFilter::default().set("exitCode", "x").is_err());
    }

    #[test]
    fn label_selectors_match_key_and_key_value() {
        let mut st = state(Status::Running, None);
        st.labels.insert("env".to_string(), "prod".to_string());
        let any_env = filter("label", "env");
        let prod_env = filter("label", "env=prod");
        let dev_env = filter("label", "env=dev");
        assert!(any_env.matches(&st));
        assert!(prod_env.matches(&st));
        assert!(!dev_env.matches(&st));
        assert!(PsFilter::default().set("label", "=value").is_err());
    }

    #[test]
    fn combines_name_id_image_and_net_selectors() {
        let running = state(Status::Running, None);
        let mut combined = filter("id", "0123").combined_with("name", "web");
        combined.set("image", "alpine:latest").unwrap();
        combined.set("net", "none").unwrap();
        assert!(combined.matches(&running));

        let mut mismatch = combined.clone();
        mismatch.set("net", "bridge").unwrap();
        assert!(!mismatch.matches(&running));
        assert!(!filter("name", "worker").matches(&running));
        assert!(filter("id", "0123456789ab").matches(&running));
    }

    impl PsFilter {
        fn combined_with(&self, key: &str, value: &str) -> PsFilter {
            let mut next = self.clone();
            next.set(key, value).unwrap();
            next
        }
    }

    #[test]
    fn rejects_unknown_and_empty_selectors() {
        assert!(PsFilter::default().set("name", "").is_err());
        assert!(PsFilter::default().set("image", "").is_err());
        assert!(PsFilter::default().set("net", "").is_err());
    }

    #[test]
    fn status_selector_widens_default_ps_view() {
        assert!(filter("status", "exited").widens_status());
        assert!(filter("status", "created").widens_status());
        assert!(filter("exitCode", "0").widens_status());
        assert!(!filter("status", "running").widens_status());
        assert!(!filter("name", "web").widens_status());
    }
}
