//! Detached-container restart policy.
//!
//! The policy is evaluated by the per-container reaper between runs. Kernel
//! resources and the writable overlay are recreated by the normal isolation
//! path; the reaper process itself stays alive so no daemon is required.

use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// Docker-compatible restart policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RestartPolicy {
    /// Do not restart the workload automatically.
    #[default]
    No,
    /// Restart only after a non-zero exit. A retry limit of zero means
    /// unlimited attempts, matching Docker.
    OnFailure { max_retries: Option<u32> },
    /// Restart after every exit until explicitly stopped.
    Always,
    /// Restart after every exit unless explicitly stopped.
    UnlessStopped,
}

impl RestartPolicy {
    /// Whether the policy can ever restart a detached workload.
    pub fn is_enabled(self) -> bool {
        !matches!(self, Self::No)
    }

    /// Decide whether another attempt is allowed after `exit_code`.
    ///
    /// `completed_restarts` counts automatic attempts already made for this
    /// manual start. The initial run is not included.
    pub fn should_restart(self, exit_code: i32, completed_restarts: u32) -> bool {
        match self {
            Self::No => false,
            Self::OnFailure { max_retries } => {
                exit_code != 0
                    && max_retries.is_none_or(|limit| limit == 0 || completed_restarts < limit)
            }
            Self::Always | Self::UnlessStopped => true,
        }
    }
}

impl fmt::Display for RestartPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::No => f.write_str("no"),
            Self::OnFailure { max_retries: None } => f.write_str("on-failure"),
            Self::OnFailure {
                max_retries: Some(max),
            } => write!(f, "on-failure:{max}"),
            Self::Always => f.write_str("always"),
            Self::UnlessStopped => f.write_str("unless-stopped"),
        }
    }
}

impl FromStr for RestartPolicy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "no" => Ok(Self::No),
            "always" => Ok(Self::Always),
            "unless-stopped" => Ok(Self::UnlessStopped),
            "on-failure" => Ok(Self::OnFailure { max_retries: None }),
            _ => {
                let Some(raw_max) = value.strip_prefix("on-failure:") else {
                    return Err(format!(
                        "invalid --restart policy '{value}' \
                         (no|on-failure[:max-retries]|always|unless-stopped)"
                    ));
                };
                if raw_max.is_empty() {
                    return Err("--restart on-failure requires a retry count after ':'".to_string());
                }
                let max_retries = raw_max.parse::<u32>().map_err(|_| {
                    format!("invalid --restart retry count '{raw_max}' (expected u32)")
                })?;
                Ok(Self::OnFailure {
                    max_retries: Some(max_retries),
                })
            }
        }
    }
}

impl Serialize for RestartPolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for RestartPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_docker_compatible_policies() {
        assert_eq!("no".parse(), Ok(RestartPolicy::No));
        assert_eq!(
            "on-failure".parse(),
            Ok(RestartPolicy::OnFailure { max_retries: None })
        );
        assert_eq!(
            "on-failure:3".parse(),
            Ok(RestartPolicy::OnFailure {
                max_retries: Some(3)
            })
        );
        assert_eq!(
            "on-failure:0".parse(),
            Ok(RestartPolicy::OnFailure {
                max_retries: Some(0)
            })
        );
        assert_eq!("always".parse(), Ok(RestartPolicy::Always));
        assert_eq!("unless-stopped".parse(), Ok(RestartPolicy::UnlessStopped));
    }

    #[test]
    fn rejects_unknown_and_malformed_policies() {
        for value in [
            "",
            "on",
            "on-failure:",
            "on-failure:-1",
            "on-failure:nope",
            "on-failure:4294967296",
            "always:2",
            "unless-stopped:1",
        ] {
            assert!(value.parse::<RestartPolicy>().is_err(), "{value:?}");
        }
    }

    #[test]
    fn retry_limits_count_automatic_restarts() {
        let limited = RestartPolicy::OnFailure {
            max_retries: Some(2),
        };
        assert!(limited.should_restart(1, 0));
        assert!(limited.should_restart(1, 1));
        assert!(!limited.should_restart(1, 2));
        assert!(!limited.should_restart(0, 0));
        assert!(RestartPolicy::OnFailure {
            max_retries: Some(0)
        }
        .should_restart(1, u32::MAX));
        assert!(RestartPolicy::Always.should_restart(0, u32::MAX));
    }

    #[test]
    fn state_serialization_uses_the_cli_spelling() {
        let policy = RestartPolicy::OnFailure {
            max_retries: Some(7),
        };
        let json = serde_json::to_string(&policy).unwrap();
        assert_eq!(json, "\"on-failure:7\"");
        assert_eq!(
            serde_json::from_str::<RestartPolicy>(&json).unwrap(),
            policy
        );
    }
}
