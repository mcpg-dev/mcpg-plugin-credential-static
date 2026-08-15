//! Operator-supplied configuration schema for
//! `dev.mcpg.credential.static`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticConfig {
    /// Per-target credential definitions. Key is the target
    /// string operators reference via `cred://<plugin_id>/<target>`.
    pub targets: BTreeMap<String, TargetEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetEntry {
    /// Single-value credential (Bearer token, simple password).
    /// Mutually exclusive with `parts` — exactly one of `value` or
    /// `parts` MUST be set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,

    /// Multi-part credential (username/password, STS triple).
    /// Operators reference parts via `cred://plugin/target#part`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub parts: BTreeMap<String, String>,

    /// TTL the gateway-side cache uses for eviction. Default
    /// 3600 (1h). Operators set short TTLs for high-rotation
    /// secrets, longer for stable ones.
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,

    /// Identity authorization rule. Default `any` (any authenticated
    /// caller — trust_level >= header_asserted — can issue this target;
    /// anonymous callers are refused). Operators set stricter modes for
    /// shared-deploy targets; the `roles`/`groups`/`subjects` rules
    /// additionally require a cryptographically Verified identity.
    #[serde(default)]
    pub authorize: Authorize,

    /// Free-form metadata surfaced via the credential's
    /// `metadata` field (audit logs, observability).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

fn default_ttl() -> u64 {
    3600
}

/// Per-target identity-authorisation rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Authorize {
    /// Any authenticated caller (trust_level >= "header_asserted").
    #[default]
    Any,
    /// Caller must have at least one of the listed roles.
    Roles { roles: Vec<String> },
    /// Caller must have at least one of the listed groups.
    Groups { groups: Vec<String> },
    /// Caller's `subject_id` must be in the allowlist.
    Subjects { subjects: Vec<String> },
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid credential.static config JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("credential.static: `targets` must be non-empty")]
    EmptyTargets,
    #[error(
        "credential.static: target `{target}` must set exactly one of \
         `value` or `parts` (got value={has_value}, parts_empty={parts_empty})"
    )]
    InvalidValueParts {
        target: String,
        has_value: bool,
        parts_empty: bool,
    },
    #[error("credential.static: target `{target}`: ttl_seconds must be > 0")]
    InvalidTtl { target: String },
    #[error(
        "credential.static: target `{target}`: authorize.{rule} list cannot \
         be empty"
    )]
    EmptyAuthorizeList { target: String, rule: &'static str },
}

impl StaticConfig {
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        let cfg: Self = serde_json::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.targets.is_empty() {
            return Err(ConfigError::EmptyTargets);
        }
        for (target, entry) in &self.targets {
            let has_value = entry.value.is_some();
            let parts_empty = entry.parts.is_empty();
            // Exactly one of value/parts. If value is set, parts
            // must be empty. If value is None, parts must be
            // non-empty.
            if has_value != parts_empty {
                return Err(ConfigError::InvalidValueParts {
                    target: target.clone(),
                    has_value,
                    parts_empty,
                });
            }
            if entry.ttl_seconds == 0 {
                return Err(ConfigError::InvalidTtl {
                    target: target.clone(),
                });
            }
            match &entry.authorize {
                Authorize::Roles { roles } if roles.is_empty() => {
                    return Err(ConfigError::EmptyAuthorizeList {
                        target: target.clone(),
                        rule: "roles",
                    });
                }
                Authorize::Groups { groups } if groups.is_empty() => {
                    return Err(ConfigError::EmptyAuthorizeList {
                        target: target.clone(),
                        rule: "groups",
                    });
                }
                Authorize::Subjects { subjects } if subjects.is_empty() => {
                    return Err(ConfigError::EmptyAuthorizeList {
                        target: target.clone(),
                        rule: "subjects",
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_minimal_config() {
        let cfg = json!({
            "targets": {
                "tgt-1": { "value": "secret-token" }
            }
        })
        .to_string();
        let parsed = StaticConfig::parse(&cfg).unwrap();
        assert_eq!(parsed.targets.len(), 1);
        let entry = parsed.targets.get("tgt-1").unwrap();
        assert_eq!(entry.value.as_deref(), Some("secret-token"));
        assert_eq!(entry.ttl_seconds, 3600);
    }

    #[test]
    fn parses_multi_part_config() {
        let cfg = json!({
            "targets": {
                "orders-pg": {
                    "parts": { "username": "alice", "password": "secret" },
                    "ttl_seconds": 600
                }
            }
        })
        .to_string();
        let parsed = StaticConfig::parse(&cfg).unwrap();
        let entry = parsed.targets.get("orders-pg").unwrap();
        assert_eq!(entry.parts.get("username").unwrap(), "alice");
        assert_eq!(entry.ttl_seconds, 600);
    }

    #[test]
    fn rejects_both_value_and_parts() {
        let cfg = json!({
            "targets": {
                "tgt-1": {
                    "value": "x",
                    "parts": { "y": "z" }
                }
            }
        })
        .to_string();
        let err = StaticConfig::parse(&cfg).unwrap_err();
        matches!(err, ConfigError::InvalidValueParts { .. });
    }

    #[test]
    fn rejects_neither_value_nor_parts() {
        let cfg = json!({
            "targets": {
                "tgt-1": { "ttl_seconds": 60 }
            }
        })
        .to_string();
        let err = StaticConfig::parse(&cfg).unwrap_err();
        matches!(err, ConfigError::InvalidValueParts { .. });
    }

    #[test]
    fn rejects_zero_ttl() {
        let cfg = json!({
            "targets": {
                "tgt-1": { "value": "x", "ttl_seconds": 0 }
            }
        })
        .to_string();
        let err = StaticConfig::parse(&cfg).unwrap_err();
        matches!(err, ConfigError::InvalidTtl { .. });
    }

    #[test]
    fn rejects_empty_roles_authorize() {
        let cfg = json!({
            "targets": {
                "tgt-1": {
                    "value": "x",
                    "authorize": { "kind": "roles", "roles": [] }
                }
            }
        })
        .to_string();
        let err = StaticConfig::parse(&cfg).unwrap_err();
        matches!(err, ConfigError::EmptyAuthorizeList { .. });
    }
}
