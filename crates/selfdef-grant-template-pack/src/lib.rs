//! `selfdef-grant-template-pack` — 8 operator-curated grant templates.
//!
//! Each template declares (id, kind, scope, profile, ttl_seconds,
//! description). The operator picks a template + tweaks scope, the
//! daemon hands the result to selfdef-grant-issuer.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_grants_mirror::GrantKind;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// 8 canonical template ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TemplateId {
    /// Read /workspace recursive.
    ReadWorkspace,
    /// Write /workspace recursive.
    WriteWorkspace,
    /// Fetch public HTTP.
    FetchPublic,
    /// Spawn test process.
    SpawnTestProcess,
    /// Read /etc/sovereign/secrets.
    ReadSecrets,
    /// Network internal RFC1918.
    NetworkInternal,
    /// Sandbox tier 1 (minimal).
    #[serde(rename = "sandbox-tier-1")]
    SandboxTier1,
    /// Sandbox tier 2 (full chroot).
    #[serde(rename = "sandbox-tier-2")]
    SandboxTier2,
}

/// Template body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantTemplate {
    /// Id.
    pub id: TemplateId,
    /// Underlying GrantKind.
    pub kind: GrantKind,
    /// Default scope (operator may override).
    pub scope: String,
    /// Default profile (operator may override).
    pub profile: String,
    /// Default TTL.
    pub ttl_seconds: u32,
    /// Operator-readable description.
    pub description: String,
}

/// Template pack.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantTemplatePack {
    /// Schema version.
    pub schema_version: String,
    /// 8 templates.
    pub templates: Vec<GrantTemplate>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum TemplateError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 8.
    #[error("template count {0} != 8 canonical")]
    CountInvalid(usize),
    /// Missing.
    #[error("missing template: {0:?}")]
    Missing(TemplateId),
    /// Scope empty.
    #[error("template {0:?} scope empty")]
    EmptyScope(TemplateId),
    /// Profile empty.
    #[error("template {0:?} profile empty")]
    EmptyProfile(TemplateId),
    /// TTL exceeds 24h.
    #[error("template {id:?} ttl {ttl} > 86400 (24h ceiling)")]
    TtlExceeds24h {
        /// id.
        id: TemplateId,
        /// ttl.
        ttl: u32,
    },
}

const REQUIRED: [TemplateId; 8] = [
    TemplateId::ReadWorkspace, TemplateId::WriteWorkspace,
    TemplateId::FetchPublic, TemplateId::SpawnTestProcess,
    TemplateId::ReadSecrets, TemplateId::NetworkInternal,
    TemplateId::SandboxTier1, TemplateId::SandboxTier2,
];

impl GrantTemplatePack {
    /// Canonical pack.
    pub fn canonical() -> Self {
        let templates = vec![
            GrantTemplate {
                id: TemplateId::ReadWorkspace,
                kind: GrantKind::Filesystem,
                scope: "/workspace/**".into(),
                profile: "careful".into(),
                ttl_seconds: 600,
                description: "Read all files under /workspace.".into(),
            },
            GrantTemplate {
                id: TemplateId::WriteWorkspace,
                kind: GrantKind::Filesystem,
                scope: "/workspace/**".into(),
                profile: "careful".into(),
                ttl_seconds: 300,
                description: "Write files under /workspace (10-minute TTL).".into(),
            },
            GrantTemplate {
                id: TemplateId::FetchPublic,
                kind: GrantKind::Network,
                scope: "https://*.public.example.org".into(),
                profile: "careful".into(),
                ttl_seconds: 600,
                description: "HTTPS GET to public hosts (operator-curated allowlist).".into(),
            },
            GrantTemplate {
                id: TemplateId::SpawnTestProcess,
                kind: GrantKind::Capability,
                scope: "cap:proc.spawn".into(),
                profile: "careful".into(),
                ttl_seconds: 300,
                description: "Spawn test subprocess (5-min TTL).".into(),
            },
            GrantTemplate {
                id: TemplateId::ReadSecrets,
                kind: GrantKind::Filesystem,
                scope: "/etc/sovereign/secrets/*".into(),
                profile: "careful".into(),
                ttl_seconds: 60,
                description: "Read secrets directory (1-minute TTL).".into(),
            },
            GrantTemplate {
                id: TemplateId::NetworkInternal,
                kind: GrantKind::Network,
                scope: "cidr:10.0.0.0/8".into(),
                profile: "careful".into(),
                ttl_seconds: 1800,
                description: "Network egress to RFC1918 internal range.".into(),
            },
            GrantTemplate {
                id: TemplateId::SandboxTier1,
                kind: GrantKind::Sandbox,
                scope: "tier:1".into(),
                profile: "careful".into(),
                ttl_seconds: 600,
                description: "Escalate to Sandbox tier 1.".into(),
            },
            GrantTemplate {
                id: TemplateId::SandboxTier2,
                kind: GrantKind::Sandbox,
                scope: "tier:2".into(),
                profile: "careful".into(),
                ttl_seconds: 600,
                description: "Escalate to Sandbox tier 2 (full chroot).".into(),
            },
        ];
        Self {
            schema_version: SCHEMA_VERSION.into(),
            templates,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), TemplateError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(TemplateError::SchemaMismatch);
        }
        if self.templates.len() != 8 {
            return Err(TemplateError::CountInvalid(self.templates.len()));
        }
        for r in REQUIRED {
            if !self.templates.iter().any(|t| t.id == r) {
                return Err(TemplateError::Missing(r));
            }
        }
        for t in &self.templates {
            if t.scope.is_empty() { return Err(TemplateError::EmptyScope(t.id)); }
            if t.profile.is_empty() { return Err(TemplateError::EmptyProfile(t.id)); }
            if t.ttl_seconds > 86_400 {
                return Err(TemplateError::TtlExceeds24h { id: t.id, ttl: t.ttl_seconds });
            }
        }
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, id: TemplateId) -> Option<&GrantTemplate> {
        self.templates.iter().find(|t| t.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        GrantTemplatePack::canonical().validate().unwrap();
    }

    #[test]
    fn eight_templates_present() {
        let p = GrantTemplatePack::canonical();
        for r in REQUIRED {
            assert!(p.get(r).is_some(), "missing {r:?}");
        }
    }

    #[test]
    fn read_secrets_short_ttl() {
        let p = GrantTemplatePack::canonical();
        assert_eq!(p.get(TemplateId::ReadSecrets).unwrap().ttl_seconds, 60);
    }

    #[test]
    fn filesystem_grants_have_path_scope() {
        let p = GrantTemplatePack::canonical();
        for id in [TemplateId::ReadWorkspace, TemplateId::WriteWorkspace, TemplateId::ReadSecrets] {
            assert!(p.get(id).unwrap().scope.starts_with('/'));
        }
    }

    #[test]
    fn network_grants_have_url_or_cidr_scope() {
        let p = GrantTemplatePack::canonical();
        assert!(p.get(TemplateId::FetchPublic).unwrap().scope.starts_with("https://"));
        assert!(p.get(TemplateId::NetworkInternal).unwrap().scope.starts_with("cidr:"));
    }

    #[test]
    fn sandbox_grants_use_tier_scope() {
        let p = GrantTemplatePack::canonical();
        assert!(p.get(TemplateId::SandboxTier1).unwrap().scope.starts_with("tier:"));
        assert!(p.get(TemplateId::SandboxTier2).unwrap().scope.starts_with("tier:"));
    }

    #[test]
    fn ttl_exceeds_24h_caught() {
        let mut p = GrantTemplatePack::canonical();
        p.templates[0].ttl_seconds = 100_000;
        assert!(matches!(p.validate().unwrap_err(), TemplateError::TtlExceeds24h { .. }));
    }

    #[test]
    fn empty_scope_caught() {
        let mut p = GrantTemplatePack::canonical();
        p.templates[0].scope = String::new();
        assert!(matches!(p.validate().unwrap_err(), TemplateError::EmptyScope(_)));
    }

    #[test]
    fn empty_profile_caught() {
        let mut p = GrantTemplatePack::canonical();
        p.templates[0].profile = String::new();
        assert!(matches!(p.validate().unwrap_err(), TemplateError::EmptyProfile(_)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = GrantTemplatePack::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), TemplateError::SchemaMismatch));
    }

    #[test]
    fn count_invalid_caught() {
        let mut p = GrantTemplatePack::canonical();
        p.templates.pop();
        assert!(matches!(p.validate().unwrap_err(), TemplateError::CountInvalid(7)));
    }

    #[test]
    fn template_id_serde_kebab() {
        assert_eq!(serde_json::to_string(&TemplateId::ReadWorkspace).unwrap(), "\"read-workspace\"");
        assert_eq!(serde_json::to_string(&TemplateId::FetchPublic).unwrap(), "\"fetch-public\"");
        assert_eq!(serde_json::to_string(&TemplateId::SpawnTestProcess).unwrap(), "\"spawn-test-process\"");
        assert_eq!(serde_json::to_string(&TemplateId::SandboxTier1).unwrap(), "\"sandbox-tier-1\"");
    }

    #[test]
    fn pack_serde_roundtrip() {
        let p = GrantTemplatePack::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: GrantTemplatePack = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
