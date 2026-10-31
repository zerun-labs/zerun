//! Per-process POSIX resource limits (`--ulimit`).
//!
//! Cgroups bound aggregate resource use for the whole container, while rlimits
//! bound what an individual process may consume or request. They are applied in
//! the container child before capabilities and seccomp are restricted, and the
//! same persisted values are restored for detached `exec` sessions.
use crate::error::ZResult;
use crate::syscalls;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Resource {
    Core,
    Cpu,
    Data,
    FileSize,
    Locks,
    LockedMemory,
    MessageQueue,
    Nice,
    OpenFiles,
    Processes,
    ResidentSet,
    RealtimePriority,
    RealtimeTimeout,
    PendingSignals,
    Stack,
    AddressSpace,
}

impl Resource {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "core" => Self::Core,
            "cpu" => Self::Cpu,
            "data" => Self::Data,
            "fsize" => Self::FileSize,
            "locks" => Self::Locks,
            "memlock" => Self::LockedMemory,
            "msgqueue" => Self::MessageQueue,
            "nice" => Self::Nice,
            "nofile" => Self::OpenFiles,
            "nproc" => Self::Processes,
            "rss" => Self::ResidentSet,
            "rtprio" => Self::RealtimePriority,
            "rttime" => Self::RealtimeTimeout,
            "sigpending" => Self::PendingSignals,
            "stack" => Self::Stack,
            "as" => Self::AddressSpace,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Cpu => "cpu",
            Self::Data => "data",
            Self::FileSize => "fsize",
            Self::Locks => "locks",
            Self::LockedMemory => "memlock",
            Self::MessageQueue => "msgqueue",
            Self::Nice => "nice",
            Self::OpenFiles => "nofile",
            Self::Processes => "nproc",
            Self::ResidentSet => "rss",
            Self::RealtimePriority => "rtprio",
            Self::RealtimeTimeout => "rttime",
            Self::PendingSignals => "sigpending",
            Self::Stack => "stack",
            Self::AddressSpace => "as",
        }
    }

    fn native(self) -> libc::c_int {
        match self {
            Self::Core => libc::RLIMIT_CORE as libc::c_int,
            Self::Cpu => libc::RLIMIT_CPU as libc::c_int,
            Self::Data => libc::RLIMIT_DATA as libc::c_int,
            Self::FileSize => libc::RLIMIT_FSIZE as libc::c_int,
            Self::Locks => libc::RLIMIT_LOCKS as libc::c_int,
            Self::LockedMemory => libc::RLIMIT_MEMLOCK as libc::c_int,
            Self::MessageQueue => libc::RLIMIT_MSGQUEUE as libc::c_int,
            Self::Nice => libc::RLIMIT_NICE as libc::c_int,
            Self::OpenFiles => libc::RLIMIT_NOFILE as libc::c_int,
            Self::Processes => libc::RLIMIT_NPROC as libc::c_int,
            Self::ResidentSet => libc::RLIMIT_RSS as libc::c_int,
            Self::RealtimePriority => libc::RLIMIT_RTPRIO as libc::c_int,
            Self::RealtimeTimeout => libc::RLIMIT_RTTIME as libc::c_int,
            Self::PendingSignals => libc::RLIMIT_SIGPENDING as libc::c_int,
            Self::Stack => libc::RLIMIT_STACK as libc::c_int,
            Self::AddressSpace => libc::RLIMIT_AS as libc::c_int,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResourceLimit {
    resource: Resource,
    soft: u64,
    hard: u64,
}

impl ResourceLimit {
    fn parse(spec: &str) -> Result<Self, String> {
        let (name, values) = spec
            .split_once('=')
            .ok_or_else(|| format!("invalid limit '{spec}' (expected TYPE=SOFT[:HARD])"))?;
        let resource = Resource::parse(name).ok_or_else(|| {
            format!(
                "unknown limit type '{name}' (core|cpu|data|fsize|locks|memlock|msgqueue|nice|nofile|nproc|rss|rtprio|rttime|sigpending|stack|as)"
            )
        })?;
        let (soft, hard) = match values.split_once(':') {
            Some((soft, hard)) => (parse_value(soft)?, parse_value(hard)?),
            None => {
                let value = parse_value(values)?;
                (value, value)
            }
        };
        if soft > hard {
            return Err(format!(
                "invalid limit '{spec}' (soft limit must not exceed hard limit)"
            ));
        }
        Ok(Self {
            resource,
            soft,
            hard,
        })
    }

    fn canonical(&self) -> String {
        format!(
            "{}={}:{}",
            self.resource.name(),
            format_value(self.soft),
            format_value(self.hard)
        )
    }

    fn apply(&self) -> ZResult<()> {
        syscalls::set_resource_limit(self.resource.native(), self.soft, self.hard).map_err(
            |error| {
                crate::zerr!(
                    "set {} resource limit {}:{}: {error}",
                    self.resource.name(),
                    format_value(self.soft),
                    format_value(self.hard)
                )
            },
        )
    }
}

// `rlim_t` is 64-bit on the current release targets but 32-bit on some Linux
// ABIs, where the cast is required.
#[allow(clippy::unnecessary_cast)]
fn platform_max() -> u64 {
    libc::RLIM_INFINITY as u64
}

fn parse_value(raw: &str) -> Result<u64, String> {
    if raw == "-1" || raw.eq_ignore_ascii_case("unlimited") {
        return Ok(platform_max());
    }
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!(
            "invalid limit value '{raw}' (expected a non-negative integer or -1)"
        ));
    }
    let value = raw
        .parse::<u64>()
        .map_err(|_| format!("invalid limit value '{raw}' (exceeds u64)"))?;
    if value > platform_max() {
        return Err(format!(
            "limit value '{raw}' exceeds this platform's rlim_t maximum"
        ));
    }
    Ok(value)
}

fn format_value(value: u64) -> String {
    if value == platform_max() {
        "-1".to_string()
    } else {
        value.to_string()
    }
}

/// Ordered, deduplicated process limits parsed from `--ulimit` values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UlimitSet {
    limits: BTreeMap<Resource, ResourceLimit>,
}

impl UlimitSet {
    /// Parse and insert one Docker-style `TYPE=SOFT[:HARD]` value. Repeating a
    /// resource replaces the earlier value, matching Docker's last-one-wins
    /// behavior.
    pub fn insert_spec(&mut self, spec: &str) -> Result<(), String> {
        let limit = ResourceLimit::parse(spec)?;
        self.limits.insert(limit.resource, limit);
        Ok(())
    }

    /// Parse persisted/canonical values. Malformed state fails closed instead
    /// of silently dropping a limit.
    pub fn from_specs(specs: &[String]) -> Result<Self, String> {
        let mut limits = Self::default();
        for spec in specs {
            limits.insert_spec(spec)?;
        }
        Ok(limits)
    }

    pub fn is_empty(&self) -> bool {
        self.limits.is_empty()
    }

    /// Stable values suitable for state files, detached restart arguments, and
    /// generated service units.
    pub fn canonical(&self) -> Vec<String> {
        let mut limits: Vec<_> = self.limits.values().collect();
        limits.sort_by_key(|limit| limit.resource.name());
        limits.into_iter().map(ResourceLimit::canonical).collect()
    }

    pub fn apply(&self) -> ZResult<()> {
        for limit in self.limits.values() {
            limit.apply()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_value, Resource, ResourceLimit, UlimitSet};

    #[test]
    fn parses_supported_limits_and_canonicalizes_soft_equals_hard() {
        let mut limits = UlimitSet::default();
        limits.insert_spec("nofile=64").unwrap();
        limits.insert_spec("as=1:2").unwrap();
        limits.insert_spec("rttime=unlimited:-1").unwrap();
        assert_eq!(
            limits.canonical(),
            vec!["as=1:2", "nofile=64:64", "rttime=-1:-1"]
        );
    }

    #[test]
    fn repeated_resource_uses_the_last_value() {
        let mut limits = UlimitSet::default();
        limits.insert_spec("nofile=64:128").unwrap();
        limits.insert_spec("nofile=32:96").unwrap();
        assert_eq!(limits.canonical(), vec!["nofile=32:96"]);
    }

    #[test]
    fn rejects_unknown_malformed_and_inverted_limits() {
        for spec in [
            "unknown=1",
            "nofile",
            "nofile=-2",
            "nofile=abc",
            "nofile=2:1",
            "nofile=1:2:3",
            "nofile=1:",
        ] {
            assert!(
                ResourceLimit::parse(spec).is_err(),
                "{spec} should be rejected"
            );
        }
    }

    #[test]
    fn accepts_all_docker_resource_names() {
        for name in [
            "core",
            "cpu",
            "data",
            "fsize",
            "locks",
            "memlock",
            "msgqueue",
            "nice",
            "nofile",
            "nproc",
            "rss",
            "rtprio",
            "rttime",
            "sigpending",
            "stack",
            "as",
        ] {
            assert!(Resource::parse(name).is_some(), "missing resource {name}");
        }
    }

    #[test]
    fn unlimited_aliases_share_the_platform_maximum() {
        assert_eq!(
            parse_value("-1").unwrap(),
            parse_value("unlimited").unwrap()
        );
        assert_eq!(parse_value("UNLIMITED").unwrap(), super::platform_max());
    }
}
