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
                            name,
                            image: st.image.clone(),
                            detail: None,
                        }),
                        Status::Exited => events.push(Event {
                            at: st.finished.clone().unwrap_or_else(|| now.clone()),
                            action: "die",
                            id: st.id.clone(),
                            name,
                            image: st.image.clone(),
                            detail: Some(format!("exitCode={}", st.exit_code.unwrap_or(-1))),
                        }),
                        // Running -> Created never happens; ignore it.
                        Status::Created => {}
                    }
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

    fn state(id: &str, name: Option<&str>, status: Status, exit: Option<i32>) -> ContainerState {
        ContainerState {
            version: 1,
            id: id.to_string(),
            name: name.map(String::from),
            image: "alpine".to_string(),
            pid: None,
            status,
            exit_code: exit,
            created: "2026-09-10T00:00:00Z".to_string(),
            started: Some("2026-09-10T00:00:01Z".to_string()),
            finished: exit.map(|_| "2026-09-10T00:00:05Z".to_string()),
            rootless: false,
            net: "none".to_string(),
            ports: vec![],
            port_protocols: None,
            ip: None,
            cmd: vec![],
            env: vec![],
            cwd: None,
            user: None,
            log: String::new(),
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
    fn rendering_matches_docker_like_shape() {
        let st = state("abc123def456", Some("web"), Status::Exited, Some(3));
        let events = diff_events(&[], &[st]);
        let line = format_event(&events[2]);
        assert_eq!(
            line,
            "2026-09-10T00:00:05Z container die (id=abc123def456, image=alpine, name=web, exitCode=3)"
        );
    }
}
