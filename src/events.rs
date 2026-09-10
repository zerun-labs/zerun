//! Container lifecycle events derived from filesystem state (`zerun events`).
//!
//! Daemonless constraint: there is no daemon to subscribe to, so events are
//! diffed from the persisted state records on a short poll. Transitions are
//! reconstructed the same way Docker replays them: a container first seen as
//! Running emits create+start, first seen as Exited emits create+start+die,
//! and a vanished record is a destroy. State timestamps anchor the events so
//! a slow poll still reports when things actually happened.

use crate::state::{ContainerState, Status};
use std::collections::HashMap;

/// One lifecycle event ready for rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// When the underlying transition happened (state timestamp or now).
    pub at: String,
    pub action: &'static str,
    pub id: String,
    pub name: Option<String>,
    pub image: String,
    /// Extra key=value detail (exit code, old name...).
    pub detail: Option<String>,
}

/// Client-side selection rules for the daemonless event poll.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EventFilter {
    action: Option<String>,
    container: Option<String>,
    name: Option<String>,
    image: Option<String>,
    exit_code: Option<i32>,
}

impl EventFilter {
    /// Set one Docker-style `key=value` selector.
    pub fn set(&mut self, key: &str, value: &str) -> Result<(), String> {
        let invalid = |what: &str| Err(format!("invalid {what}: {value:?}"));
        match key {
            "action" | "event" => {
                self.action = Some(value.to_string());
                Ok(())
            }
            "container" => {
                if value.is_empty() {
                    return invalid("container");
                }
                self.container = Some(value.to_string());
                Ok(())
            }
            "name" => {
                if value.is_empty() {
                    return invalid("name");
                }
                self.name = Some(value.to_string());
                Ok(())
            }
            "image" => {
                if value.is_empty() {
                    return invalid("image");
                }
                self.image = Some(value.to_string());
                Ok(())
            }
            "exitCode" => match value.parse::<i32>() {
                Ok(code) => {
                    self.exit_code = Some(code);
                    Ok(())
                }
                Err(_) => invalid("exit code"),
            },
            _ => Err(format!("unknown event filter {key:?}")),
        }
    }

    fn matches(&self, event: &Event) -> bool {
        let action_ok = self
            .action
            .as_ref()
            .is_none_or(|want| event.action == want.as_str());
        let container_ok = self.container.as_ref().is_none_or(|want| {
            event.id == *want
                || event.id.starts_with(want)
                || event.name.as_deref() == Some(want.as_str())
        });
        let name_ok = self
            .name
            .as_ref()
            .is_none_or(|want| event.name.as_deref() == Some(want.as_str()));
        let image_ok = self.image.as_ref().is_none_or(|want| event.image == *want);
        let exit_ok = self.exit_code.as_ref().is_none_or(|want| {
            event
                .detail
                .as_deref()
                .and_then(|detail| detail.strip_prefix("exitCode="))
                .and_then(|code| code.parse::<i32>().ok())
                == Some(*want)
        });
        action_ok && container_ok && name_ok && image_ok && exit_ok
    }
}

/// Include only events whose timestamp is in `[since, until]`. State
/// timestamps are normalized RFC3339 UTC, so lexical order matches time order.
fn in_time_range(event: &Event, since: Option<&str>, until: Option<&str>) -> bool {
    since.is_none_or(|since| event.at.as_str() >= since)
        && until.is_none_or(|until| event.at.as_str() <= until)
}

/// Apply every filter (AND) and the inclusive timestamp range.
pub fn select_events(
    events: Vec<Event>,
    filters: &[EventFilter],
    since: Option<&str>,
    until: Option<&str>,
) -> Vec<Event> {
    events
        .into_iter()
        .filter(|event| {
            in_time_range(event, since, until) && filters.iter().all(|filter| filter.matches(event))
        })
        .collect()
}
/// Render an event in a Docker-events-like one-line format.
pub fn format_event(event: &Event) -> String {
    let mut line = format!(
        "{} container {} (id={}, image={}",
        event.at, event.action, event.id, event.image
    );
    if let Some(name) = &event.name {
        line.push_str(&format!(", name={name}"));
    }
    if let Some(detail) = &event.detail {
        line.push_str(&format!(", {detail}"));
    }
    line.push(')');
    line
}

/// Diff the previous snapshot against the current one, oldest transition
/// first within a container's emitted history.
pub fn diff_events(previous: &[ContainerState], current: &[ContainerState]) -> Vec<Event> {
    let prev: HashMap<&str, &ContainerState> =
        previous.iter().map(|s| (s.id.as_str(), s)).collect();
    let now = crate::state::now_rfc3339();
    let mut events = Vec::new();
    for st in current {
        let name = st.name.clone();
        let created = Event {
            at: st.created.clone(),
            action: "create",
            id: st.id.clone(),
            name: name.clone(),
            image: st.image.clone(),
            detail: None,
        };
        match prev.get(st.id.as_str()) {
            None => {
                // Replay this container's history up to its current status.
                events.push(created);
                if st.status == Status::Running || st.status == Status::Exited {
                    events.push(Event {
                        at: st.started.clone().unwrap_or_else(|| now.clone()),
                        action: "start",
                        id: st.id.clone(),
                        name: name.clone(),
                        image: st.image.clone(),
                        detail: None,
                    });
                }
                if st.status == Status::Exited {
                    events.push(Event {
                        at: st.finished.clone().unwrap_or_else(|| now.clone()),
                        action: "die",
                        id: st.id.clone(),
                        name: name.clone(),
                        image: st.image.clone(),
                        detail: Some(format!("exitCode={}", st.exit_code.unwrap_or(-1))),
                    });
                }
                if st.status == Status::Running && st.paused {
                    events.push(Event {
                        at: now.clone(),
                        action: "pause",
                        id: st.id.clone(),
                        name: name.clone(),
                        image: st.image.clone(),
                        detail: None,
                    });
                }
            }
            Some(old) => {
                if old.name != st.name {
                    events.push(Event {
                        at: now.clone(),
                        action: "rename",
                        id: st.id.clone(),
                        name: st.name.clone(),
                        image: st.image.clone(),
                        detail: Some(format!(
                            "from={} to={}",
                            old.name.clone().unwrap_or_else(|| st.id.clone()),
                            st.name.clone().unwrap_or_else(|| st.id.clone())
                        )),
                    });
                }
                if old.status != st.status {
                    match st.status {
                        Status::Running => events.push(Event {
                            at: st.started.clone().unwrap_or_else(|| now.clone()),
                            action: "start",
                            id: st.id.clone(),
                            name: name.clone(),
                            image: st.image.clone(),
                            detail: None,
                        }),
                        Status::Exited => events.push(Event {
                            at: st.finished.clone().unwrap_or_else(|| now.clone()),
                            action: "die",
                            id: st.id.clone(),
                            name: name.clone(),
                            image: st.image.clone(),
                            detail: Some(format!("exitCode={}", st.exit_code.unwrap_or(-1))),
                        }),
                        // Running -> Created never happens; ignore it.
                        Status::Created => {}
                    }
                }
                if old.status == Status::Running
                    && st.status == Status::Running
                    && old.paused != st.paused
                {
                    events.push(Event {
                        at: now.clone(),
                        action: if st.paused { "pause" } else { "unpause" },
                        id: st.id.clone(),
                        name: name.clone(),
                        image: st.image.clone(),
                        detail: None,
                    });
                }
            }
        }
    }
    // Records that disappeared are destroys; the old record anchors names.
    for old in previous {
        if !current.iter().any(|s| s.id == old.id) {
            events.push(Event {
                at: now.clone(),
                action: "destroy",
                id: old.id.clone(),
                name: old.name.clone(),
                image: old.image.clone(),
                detail: None,
            });
        }
    }
    // State timestamps are RFC3339 UTC, so lexicographic order is
    // chronological and the stream is stable across poll boundaries.
    events.sort_by(|a, b| a.at.cmp(&b.at).then(a.id.cmp(&b.id)));
    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn state(id: &str, name: Option<&str>, status: Status, exit: Option<i32>) -> ContainerState {
        ContainerState {
            version: 1,
            id: id.to_string(),
            name: name.map(String::from),
            image: "alpine".to_string(),
            pid: None,
            status,
            paused: false,
            exit_code: exit,
            created: "2026-09-10T00:00:00Z".to_string(),
            started: Some("2026-09-10T00:00:01Z".to_string()),
            finished: exit.map(|_| "2026-09-10T00:00:05Z".to_string()),
            rootless: false,
            net: "none".to_string(),
            ports: vec![],
            port_protocols: None,
            port_ips: None,
            ip: None,
            cmd: vec![],
            env: vec![],
            cwd: None,
            user: None,
            capabilities: None,
            seccomp: None,
            labels: BTreeMap::new(),
            log: String::new(),
            log_max_size: None,
            log_max_file: None,
            lower: Some("/tmp/zerun-events/lower".to_string()),
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

    #[test]
    fn new_running_replays_create_and_start() {
        let st = state("abc123", Some("web"), Status::Running, None);
        let events = diff_events(&[], &[st]);
        let actions: Vec<&str> = events.iter().map(|e| e.action).collect();
        assert_eq!(actions, vec!["create", "start"]);
    }

    #[test]
    fn new_exited_replays_full_history() {
        let st = state("abc123", Some("web"), Status::Exited, Some(42));
        let events = diff_events(&[], &[st]);
        let actions: Vec<&str> = events.iter().map(|e| e.action).collect();
        assert_eq!(actions, vec!["create", "start", "die"]);
        assert_eq!(events[2].detail.as_deref(), Some("exitCode=42"));
    }

    #[test]
    fn transitions_and_rename_are_detected() {
        let old = state("abc123", Some("web"), Status::Running, None);
        let new = state("abc123", Some("api"), Status::Exited, Some(0));
        let events = diff_events(&[old], std::slice::from_ref(&new));
        // rename is anchored at the poll time (state has no rename stamp),
        // so the chronological sort emits the earlier die first.
        let actions: Vec<&str> = events.iter().map(|e| e.action).collect();
        assert_eq!(actions, vec!["die", "rename"]);
        assert_eq!(events[1].detail.as_deref(), Some("from=web to=api"));

        let renamed_only = diff_events(
            &[state("abc123", Some("web"), Status::Exited, Some(0))],
            &[new],
        );
        let actions: Vec<&str> = renamed_only.iter().map(|e| e.action).collect();
        assert_eq!(actions, vec!["rename"]);
    }

    #[test]
    fn vanished_records_emit_destroy() {
        let old = state("abc123", Some("web"), Status::Exited, Some(0));
        let events = diff_events(&[old], &[]);
        let actions: Vec<&str> = events.iter().map(|e| e.action).collect();
        assert_eq!(actions, vec!["destroy"]);
    }

    #[test]
    fn pause_and_unpause_transitions_are_detected() {
        let running = state("abc123", Some("web"), Status::Running, None);
        let mut paused = state("abc123", Some("web"), Status::Running, None);
        paused.paused = true;
        let paused_events = diff_events(
            std::slice::from_ref(&running),
            std::slice::from_ref(&paused),
        );
        assert_eq!(paused_events[0].action, "pause");

        let resumed = diff_events(&[paused], &[running]);
        assert_eq!(resumed[0].action, "unpause");
    }

    #[test]
    fn rendering_matches_docker_like_shape() {
        let st = state("abc123def456", Some("web"), Status::Exited, Some(3));
        let events = diff_events(&[], &[st]);
        let line = format_event(&events[2]);
        assert_eq!(
            line,
            "2026-09-10T00:00:05Z container die (id=abc123def456, image=alpine, name=web, exitCode=3)"
        );
    }

    #[test]
    fn event_filters_match_precise_and_container_prefixes() {
        let st = state("abc123def456", Some("web"), Status::Exited, Some(3));
        let events = diff_events(&[], &[st]);

        let mut filter = EventFilter::default();
        filter.set("action", "die").unwrap();
        filter.set("container", "abc").unwrap();
        assert_eq!(
            select_events(events.clone(), &[filter], None, None).len(),
            1
        );

        let mut filter = EventFilter::default();
        filter.set("exitCode", "4").unwrap();
        assert!(select_events(events.clone(), &[filter], None, None).is_empty());

        let mut filter = EventFilter::default();
        assert!(filter.set("type", "container").is_err());
    }

    #[test]
    fn event_time_ranges_are_inclusive() {
        let st = state("abc123def456", Some("web"), Status::Exited, Some(3));
        let events = diff_events(&[], &[st]);
        let die_at = events[2].at.clone();

        assert_eq!(
            select_events(events.clone(), &[], Some(&die_at), Some(&die_at)).len(),
            1
        );
        assert!(select_events(events, &[], Some("9999"), None).is_empty());
    }
}
