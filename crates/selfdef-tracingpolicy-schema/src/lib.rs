//! `selfdef-tracingpolicy-schema` — MS017 Tetragon TracingPolicy emission shape.
//!
//! Per MS017 + MS016 + dump 549-556. Tetragon TracingPolicy is a YAML
//! / JSON object the daemon writes to `/etc/tetragon/policies/` that
//! Tetragon consumes to install kprobe + tracepoint hooks.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version of the typed schema.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Canonical Tetragon apiVersion.
pub const TETRAGON_API_VERSION: &str = "cilium.io/v1alpha1";

/// Canonical Tetragon kind.
pub const TETRAGON_KIND: &str = "TracingPolicy";

/// Operator-supplied directory where the daemon drops policies.
pub const POLICY_DROP_DIR: &str = "/etc/tetragon/policies";

/// Hook type for the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookType {
    /// Kernel probe (kprobe).
    Kprobe,
    /// Tracepoint.
    Tracepoint,
    /// uretprobe (user-space return probe).
    Uretprobe,
}

/// Selector clause for filtering events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Selector {
    /// match-args clause (kprobe argument index list).
    pub match_args: Vec<u8>,
    /// match-binaries (process name allowlist or denylist).
    pub match_binaries: Vec<String>,
    /// match-pid-ns (container PID namespace filter).
    pub match_pid_ns: bool,
    /// action when selector matches (e.g. "SIGKILL", "Override", "FollowFD").
    pub action: String,
}

/// One TracingPolicy spec.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicySpec {
    /// Hook type.
    pub hook: HookType,
    /// Symbol to attach to (e.g. "sys_execve", "do_sys_openat2").
    pub symbol: String,
    /// Whether this is a return probe (kretprobe).
    pub r#return: bool,
    /// Selectors applied to events.
    pub selectors: Vec<Selector>,
}

/// Top-level TracingPolicy object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TracingPolicy {
    /// apiVersion — MUST equal TETRAGON_API_VERSION.
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    /// kind — MUST equal TETRAGON_KIND.
    pub kind: String,
    /// Metadata block — name + operator-supplied labels.
    pub metadata: PolicyMetadata,
    /// Spec.
    pub spec: PolicySpec,
    /// MS003 signature over the canonical-JSON envelope (hex).
    pub signature: String,
}

/// Metadata block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyMetadata {
    /// Policy name (DNS-1123 subdomain).
    pub name: String,
    /// Operator-supplied labels.
    pub labels: std::collections::BTreeMap<String, String>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// apiVersion wrong.
    #[error("apiVersion mismatch: expected {TETRAGON_API_VERSION}, got {0}")]
    ApiVersionMismatch(String),
    /// kind wrong.
    #[error("kind mismatch: expected {TETRAGON_KIND}, got {0}")]
    KindMismatch(String),
    /// Empty field.
    #[error("required field empty: {0}")]
    FieldEmpty(&'static str),
    /// Signature missing.
    #[error("policy unsigned (MS003 signature required for delivery to /etc/tetragon/policies)")]
    Unsigned,
    /// Selector action not in known-good set.
    #[error("selector action not in allow-set: {0}")]
    UnknownAction(String),
    /// DNS-1123 violation in name.
    #[error("name not DNS-1123 subdomain: {0}")]
    NameInvalid(String),
}

/// Known-good selector actions (Tetragon-supported).
pub const ALLOWED_ACTIONS: &[&str] = &[
    "SIGKILL",
    "Override",
    "FollowFD",
    "UnfollowFD",
    "CopyFD",
    "Post",
    "GetUrl",
    "DnsLookup",
    "NoPost",
    "Signal",
];

fn is_dns_1123_label(s: &str) -> bool {
    if s.is_empty() || s.len() > 63 {
        return false;
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return false;
    }
    if s.starts_with('-') || s.ends_with('-') {
        return false;
    }
    true
}

fn is_dns_1123_subdomain(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(is_dns_1123_label)
}

impl TracingPolicy {
    /// Validate envelope shape.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.api_version != TETRAGON_API_VERSION {
            return Err(PolicyError::ApiVersionMismatch(self.api_version.clone()));
        }
        if self.kind != TETRAGON_KIND {
            return Err(PolicyError::KindMismatch(self.kind.clone()));
        }
        if !is_dns_1123_subdomain(&self.metadata.name) {
            return Err(PolicyError::NameInvalid(self.metadata.name.clone()));
        }
        if self.spec.symbol.is_empty() {
            return Err(PolicyError::FieldEmpty("spec.symbol"));
        }
        if self.signature.is_empty() {
            return Err(PolicyError::Unsigned);
        }
        for sel in &self.spec.selectors {
            if !ALLOWED_ACTIONS.contains(&sel.action.as_str()) {
                return Err(PolicyError::UnknownAction(sel.action.clone()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn ok_policy() -> TracingPolicy {
        TracingPolicy {
            api_version: TETRAGON_API_VERSION.into(),
            kind: TETRAGON_KIND.into(),
            metadata: PolicyMetadata {
                name: "agent-guard-execve".into(),
                labels: BTreeMap::new(),
            },
            spec: PolicySpec {
                hook: HookType::Kprobe,
                symbol: "sys_execve".into(),
                r#return: false,
                selectors: vec![Selector {
                    match_args: vec![0, 1],
                    match_binaries: vec!["/usr/bin/python3".into()],
                    match_pid_ns: true,
                    action: "SIGKILL".into(),
                }],
            },
            signature: "ms003-sig".into(),
        }
    }

    #[test]
    fn ok_policy_validates() {
        ok_policy().validate().unwrap();
    }

    #[test]
    fn wrong_api_version_rejected() {
        let mut p = ok_policy();
        p.api_version = "v1".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            PolicyError::ApiVersionMismatch(_)
        ));
    }

    #[test]
    fn wrong_kind_rejected() {
        let mut p = ok_policy();
        p.kind = "WrongKind".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            PolicyError::KindMismatch(_)
        ));
    }

    #[test]
    fn empty_symbol_rejected() {
        let mut p = ok_policy();
        p.spec.symbol = String::new();
        assert!(matches!(
            p.validate().unwrap_err(),
            PolicyError::FieldEmpty("spec.symbol")
        ));
    }

    #[test]
    fn unsigned_rejected() {
        let mut p = ok_policy();
        p.signature = String::new();
        assert!(matches!(p.validate().unwrap_err(), PolicyError::Unsigned));
    }

    #[test]
    fn unknown_action_rejected() {
        let mut p = ok_policy();
        p.spec.selectors[0].action = "Unauthorized".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            PolicyError::UnknownAction(_)
        ));
    }

    #[test]
    fn dns_1123_name_validators() {
        // Valid labels
        assert!(is_dns_1123_label("agent-guard"));
        assert!(is_dns_1123_label("a"));
        // Invalid: empty / starts with dash / uppercase / underscore
        assert!(!is_dns_1123_label(""));
        assert!(!is_dns_1123_label("-bad"));
        assert!(!is_dns_1123_label("bad-"));
        assert!(!is_dns_1123_label("Bad"));
        assert!(!is_dns_1123_label("bad_name"));
        // Subdomain composed of labels
        assert!(is_dns_1123_subdomain("agent-guard.system"));
    }

    #[test]
    fn invalid_name_rejected() {
        let mut p = ok_policy();
        p.metadata.name = "Bad Name!".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            PolicyError::NameInvalid(_)
        ));
    }

    #[test]
    fn allowed_actions_includes_canonical() {
        for a in ["SIGKILL", "Override", "FollowFD", "Post", "Signal"] {
            assert!(ALLOWED_ACTIONS.contains(&a));
        }
    }

    #[test]
    fn hook_type_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&HookType::Kprobe).unwrap(),
            "\"kprobe\""
        );
        assert_eq!(
            serde_json::to_string(&HookType::Uretprobe).unwrap(),
            "\"uretprobe\""
        );
        assert_eq!(
            serde_json::to_string(&HookType::Tracepoint).unwrap(),
            "\"tracepoint\""
        );
    }

    #[test]
    fn policy_serde_roundtrip_with_apiversion_field() {
        let p = ok_policy();
        let j = serde_json::to_string(&p).unwrap();
        assert!(j.contains("\"apiVersion\""));
        let back: TracingPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn api_version_constant_canonical() {
        assert_eq!(TETRAGON_API_VERSION, "cilium.io/v1alpha1");
        assert_eq!(TETRAGON_KIND, "TracingPolicy");
        assert_eq!(POLICY_DROP_DIR, "/etc/tetragon/policies");
    }
}
