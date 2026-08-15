//! `dev.mcpg.credential.static` — config-driven static
//! credential_issuer plugin.
//!
//! Operators declare per-target credentials in YAML; the plugin
//! returns them per-request keyed on the target string. Pure
//! offline; no outbound network. Useful for dev / lab / partner
//! integrations + as the integration test foundation for the
//! credential_issuer trait surface.
//!
//! Production deployments needing dynamic Vault DB credentials
//! use the `dev.mcpg.credential.vault-dynamic-db` plugin instead.

pub mod config;

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use mcpg_plugin_protocol::PluginManifest;
use mcpg_plugin_protocol::credential::{CredentialError, CredentialIssuer, IssuedCredential};
use mcpg_plugin_protocol::manifest::PluginClass;
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncCredentialIssuer;
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub use config::{Authorize, ConfigError, StaticConfig, TargetEntry};

const PLUGIN_ID: &str = "dev.mcpg.credential.static";

pub struct StaticCredentialPlugin {
    inner: Arc<Inner>,
}

struct Inner {
    manifest: PluginManifest,
    targets: BTreeMap<String, TargetEntry>,
}

impl StaticCredentialPlugin {
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg = StaticConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                "credential.static: config parse failed; refusing to register"
            );
            panic!(
                "credential.static config parse failed: {err}. A misconfigured \
                 credential issuer is a security hole; refusing to load."
            )
        });
        Self::from_validated_config(cfg)
    }

    fn from_validated_config(cfg: StaticConfig) -> Self {
        tracing::info!(
            plugin_id = PLUGIN_ID,
            targets_loaded = cfg.targets.len(),
            "credential.static: registry compiled"
        );
        Self {
            inner: Arc::new(Inner {
                manifest: PluginManifest {
                    id: PLUGIN_ID.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    name: "Static Credential Issuer".into(),
                    plugin_class: PluginClass::CredentialIssuer,
                    protocol_version: "1.0".into(),
                    license: None,
                    required_capabilities: Vec::new(),
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
                targets: cfg.targets,
            }),
        }
    }
}

fn check_authorization(
    target: &str,
    rule: &Authorize,
    identity: &PluginIdentity,
) -> Result<(), CredentialError> {
    use mcpg_plugin_protocol::catalog::{
        TRUST_LEVEL_HEADER_ASSERTED, TRUST_LEVEL_VERIFIED, trust_level_meets,
    };
    let trust = identity.trust_level.as_str();
    let authorized = match rule {
        // "Any authenticated caller" — the documented floor is
        // header_asserted, so an Anonymous caller never qualifies. This
        // is the default rule for every target, so it must not hand a
        // secret to a completely unauthenticated request.
        Authorize::Any => trust_level_meets(trust, TRUST_LEVEL_HEADER_ASSERTED),
        // Identity-derived rules only carry meaning when the identity
        // itself is cryptographically Verified: at header_asserted trust
        // the `subject_id` is the spoofable `x-mcpg-subject-id` header
        // and roles/groups are empty. Require Verified before honouring
        // any of them — otherwise a forged header could match a subject
        // allowlist and exfiltrate another principal's credential.
        Authorize::Roles { roles } => {
            trust_level_meets(trust, TRUST_LEVEL_VERIFIED)
                && roles.iter().any(|r| identity.roles.contains(r))
        }
        Authorize::Groups { groups } => {
            trust_level_meets(trust, TRUST_LEVEL_VERIFIED)
                && groups.iter().any(|g| identity.groups.contains(g))
        }
        Authorize::Subjects { subjects } => {
            trust_level_meets(trust, TRUST_LEVEL_VERIFIED)
                && identity
                    .subject_id
                    .as_ref()
                    .is_some_and(|s| subjects.iter().any(|allowed| allowed == s))
        }
    };
    if authorized {
        Ok(())
    } else {
        Err(CredentialError::NotAuthorized {
            reason: format!("identity not permitted to issue target `{target}`"),
        })
    }
}

fn issue_for(
    inner: &Inner,
    identity: &PluginIdentity,
    target: &str,
) -> Result<IssuedCredential, CredentialError> {
    let entry = inner
        .targets
        .get(target)
        .ok_or_else(|| CredentialError::Misconfigured {
            reason: format!("unknown target `{target}` in credential.static plugin"),
        })?;
    check_authorization(target, &entry.authorize, identity)?;
    let issued_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default();
    Ok(IssuedCredential {
        value: entry.value.clone(),
        parts: entry.parts.clone(),
        ttl_seconds: entry.ttl_seconds,
        lease_id: None,
        issued_at,
        metadata: entry.metadata.clone(),
    })
}

#[async_trait]
impl CredentialIssuer for StaticCredentialPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    async fn issue(
        &self,
        identity: &PluginIdentity,
        target: &str,
        _config: &Value,
    ) -> Result<IssuedCredential, CredentialError> {
        issue_for(&self.inner, identity, target)
    }

    // No-op revoke — static credentials don't have leases.
}

impl SyncCredentialIssuer for StaticCredentialPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn issue(
        &self,
        identity: &PluginIdentity,
        target: &str,
        _config: &Value,
    ) -> Result<IssuedCredential, CredentialError> {
        issue_for(&self.inner, identity, target)
    }
}

declare_plugin! {
    plugin_id: "dev.mcpg.credential.static",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[],
    entities: [
        credential_issuer as entity {
            inner_name: "",
            plugin_type: StaticCredentialPlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| -> StaticCredentialPlugin {
                StaticCredentialPlugin::from_config_json(cfg)
            },
        }
    ],
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn build(cfg: serde_json::Value) -> StaticCredentialPlugin {
        StaticCredentialPlugin::from_config_json(&cfg.to_string())
    }

    fn identity_with(roles: &[&str], groups: &[&str], subject: &str) -> PluginIdentity {
        PluginIdentity {
            kind: "verified".into(),
            trust_level: "verified".into(),
            subject_id: Some(subject.into()),
            auth_provider: None,
            issuer: None,
            roles: roles.iter().map(|s| (*s).to_owned()).collect(),
            groups: groups.iter().map(|s| (*s).to_owned()).collect(),
            scopes: vec![],
            attributes: BTreeMap::new(),
        }
    }

    fn identity_at_trust(trust_level: &str, subject: &str) -> PluginIdentity {
        PluginIdentity {
            kind: trust_level.into(),
            trust_level: trust_level.into(),
            subject_id: Some(subject.into()),
            auth_provider: None,
            issuer: None,
            roles: vec![],
            groups: vec![],
            scopes: vec![],
            attributes: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn issues_single_value_credential() {
        let plugin = build(json!({
            "targets": {
                "service-token": { "value": "tok-abc", "ttl_seconds": 60 }
            }
        }));
        let cred = CredentialIssuer::issue(
            &plugin,
            &identity_with(&[], &[], "alice"),
            "service-token",
            &json!({}),
        )
        .await
        .unwrap();
        assert_eq!(cred.value.as_deref(), Some("tok-abc"));
        assert_eq!(cred.ttl_seconds, 60);
    }

    #[tokio::test]
    async fn issues_multi_part_credential() {
        let plugin = build(json!({
            "targets": {
                "orders-pg": {
                    "parts": { "username": "u", "password": "p" }
                }
            }
        }));
        let cred = CredentialIssuer::issue(
            &plugin,
            &identity_with(&[], &[], "alice"),
            "orders-pg",
            &json!({}),
        )
        .await
        .unwrap();
        assert_eq!(cred.parts.get("username").unwrap(), "u");
        assert_eq!(cred.parts.get("password").unwrap(), "p");
    }

    #[tokio::test]
    async fn unknown_target_returns_misconfigured() {
        let plugin = build(json!({
            "targets": { "x": { "value": "y" } }
        }));
        let err = CredentialIssuer::issue(
            &plugin,
            &identity_with(&[], &[], "alice"),
            "missing",
            &json!({}),
        )
        .await
        .unwrap_err();
        match err {
            CredentialError::Misconfigured { reason } => assert!(reason.contains("missing")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn roles_rule_blocks_non_role_holders() {
        let plugin = build(json!({
            "targets": {
                "admin-token": {
                    "value": "admin-x",
                    "authorize": { "kind": "roles", "roles": ["admin"] }
                }
            }
        }));
        let err = CredentialIssuer::issue(
            &plugin,
            &identity_with(&["dev"], &[], "alice"),
            "admin-token",
            &json!({}),
        )
        .await
        .unwrap_err();
        matches!(err, CredentialError::NotAuthorized { .. });
        let ok = CredentialIssuer::issue(
            &plugin,
            &identity_with(&["admin"], &[], "alice"),
            "admin-token",
            &json!({}),
        )
        .await;
        assert!(ok.is_ok());
    }

    #[tokio::test]
    async fn subjects_rule_allowlists_specific_users() {
        let plugin = build(json!({
            "targets": {
                "alice-only": {
                    "value": "x",
                    "authorize": { "kind": "subjects", "subjects": ["alice"] }
                }
            }
        }));
        assert!(
            CredentialIssuer::issue(
                &plugin,
                &identity_with(&[], &[], "alice"),
                "alice-only",
                &json!({}),
            )
            .await
            .is_ok()
        );
        assert!(matches!(
            CredentialIssuer::issue(
                &plugin,
                &identity_with(&[], &[], "bob"),
                "alice-only",
                &json!({}),
            )
            .await
            .unwrap_err(),
            CredentialError::NotAuthorized { .. }
        ));
    }

    #[tokio::test]
    async fn any_rule_rejects_anonymous_caller() {
        // L-43: the default `Authorize::Any` rule must not hand a secret
        // to an unauthenticated (anonymous) caller.
        let plugin = build(json!({
            "targets": { "default-tok": { "value": "secret" } }
        }));
        assert!(matches!(
            CredentialIssuer::issue(
                &plugin,
                &identity_at_trust("anonymous", "whoever"),
                "default-tok",
                &json!({}),
            )
            .await
            .unwrap_err(),
            CredentialError::NotAuthorized { .. }
        ));
        // A header-asserted caller meets the documented floor.
        assert!(
            CredentialIssuer::issue(
                &plugin,
                &identity_at_trust("header_asserted", "whoever"),
                "default-tok",
                &json!({}),
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn subjects_rule_rejects_header_asserted_subject() {
        // H-8: a spoofable header-asserted `subject_id` must NOT satisfy a
        // subject allowlist — only a Verified identity may.
        let plugin = build(json!({
            "targets": {
                "alice-only": {
                    "value": "x",
                    "authorize": { "kind": "subjects", "subjects": ["alice"] }
                }
            }
        }));
        assert!(matches!(
            CredentialIssuer::issue(
                &plugin,
                &identity_at_trust("header_asserted", "alice"),
                "alice-only",
                &json!({}),
            )
            .await
            .unwrap_err(),
            CredentialError::NotAuthorized { .. }
        ));
        // The same subject at Verified trust is allowed.
        assert!(
            CredentialIssuer::issue(
                &plugin,
                &identity_with(&[], &[], "alice"),
                "alice-only",
                &json!({}),
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn issued_at_is_rfc3339() {
        let plugin = build(json!({
            "targets": { "x": { "value": "y" } }
        }));
        let cred =
            CredentialIssuer::issue(&plugin, &identity_with(&[], &[], "alice"), "x", &json!({}))
                .await
                .unwrap();
        // RFC3339 timestamps are 20+ chars: "YYYY-MM-DDTHH:MM:SSZ"
        assert!(cred.issued_at.len() >= 20);
        assert!(cred.issued_at.contains('T'));
    }
}
