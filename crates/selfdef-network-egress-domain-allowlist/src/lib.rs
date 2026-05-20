//! `selfdef-network-egress-domain-allowlist` — per-Profile FQDN allowlist.
//!
//! Match rules per allowed entry:
//!   * exact FQDN: `api.example.com` matches only itself.
//!   * subdomain wildcard: `*.example.com` matches `a.example.com`,
//!     `a.b.example.com`, but NOT bare `example.com`.
//!   * full wildcard `*` matches any host.
//!
//! Matching is case-insensitive.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// Private.
    Private,
    /// Fast.
    Fast,
    /// Careful.
    Careful,
    /// Autonomous.
    Autonomous,
    /// Experimental.
    Experimental,
    /// Production.
    Production,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkEgressDomainAllowlist {
    /// Schema version.
    pub schema_version: String,
    /// profile → host rules.
    pub profiles: BTreeMap<Profile, BTreeSet<String>>,
}

/// Verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DomainVerdict {
    /// Allowed.
    Allowed {
        /// matched rule.
        matched: String,
    },
    /// Denied.
    Denied {
        /// number of rules in the profile.
        allowed_count: usize,
    },
    /// Unconfigured.
    Unconfigured,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DomainError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty host.
    #[error("host empty")]
    EmptyHost,
    /// Bad rule.
    #[error("bad rule: {0}")]
    BadRule(String),
}

impl NetworkEgressDomainAllowlist {
    /// Canonical.
    pub fn canonical() -> Self {
        let mut p = BTreeMap::new();
        p.insert(Profile::Private,      BTreeSet::new());
        p.insert(Profile::Fast,         ["*.huggingface.co".into(), "raw.githubusercontent.com".into()].into_iter().collect());
        p.insert(Profile::Careful,      BTreeSet::new());
        p.insert(Profile::Autonomous,   ["*.huggingface.co".into(), "*.github.com".into(), "api.anthropic.com".into()].into_iter().collect());
        p.insert(Profile::Experimental, ["*".into()].into_iter().collect());
        p.insert(Profile::Production,   ["api.anthropic.com".into(), "*.huggingface.co".into()].into_iter().collect());
        Self {
            schema_version: SCHEMA_VERSION.into(),
            profiles: p,
        }
    }

    /// Classify.
    pub fn classify(&self, profile: Profile, host: &str) -> Result<DomainVerdict, DomainError> {
        if host.is_empty() { return Err(DomainError::EmptyHost); }
        let h = host.to_ascii_lowercase();
        let set = match self.profiles.get(&profile) {
            Some(s) => s,
            None => return Ok(DomainVerdict::Unconfigured),
        };
        if set.contains("*") {
            return Ok(DomainVerdict::Allowed { matched: "*".into() });
        }
        for rule in set {
            if rule == "*" { continue; }
            let rule_lc = rule.to_ascii_lowercase();
            if let Some(suffix) = rule_lc.strip_prefix("*.") {
                // suffix must NOT be empty after `*.`, and host must end with `.suffix`.
                if suffix.is_empty() {
                    return Err(DomainError::BadRule(rule.clone()));
                }
                let probe = format!(".{}", suffix);
                if h.ends_with(&probe) {
                    return Ok(DomainVerdict::Allowed { matched: rule.clone() });
                }
            } else if h == rule_lc {
                return Ok(DomainVerdict::Allowed { matched: rule.clone() });
            }
        }
        Ok(DomainVerdict::Denied { allowed_count: set.len() })
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.schema_version != SCHEMA_VERSION { return Err(DomainError::SchemaMismatch); }
        for set in self.profiles.values() {
            for r in set {
                if r.is_empty() { return Err(DomainError::EmptyHost); }
                if let Some(suffix) = r.strip_prefix("*.") {
                    if suffix.is_empty() { return Err(DomainError::BadRule(r.clone())); }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        NetworkEgressDomainAllowlist::canonical().validate().unwrap();
    }

    #[test]
    fn exact_allowed() {
        let a = NetworkEgressDomainAllowlist::canonical();
        assert!(matches!(a.classify(Profile::Production, "api.anthropic.com").unwrap(), DomainVerdict::Allowed { .. }));
    }

    #[test]
    fn wildcard_subdomain_matches_nested() {
        let a = NetworkEgressDomainAllowlist::canonical();
        let v = a.classify(Profile::Autonomous, "a.b.github.com").unwrap();
        match v {
            DomainVerdict::Allowed { matched } => assert_eq!(matched, "*.github.com"),
            _ => panic!(),
        }
    }

    #[test]
    fn wildcard_subdomain_not_bare() {
        let a = NetworkEgressDomainAllowlist::canonical();
        // *.github.com does NOT match bare github.com.
        assert!(matches!(a.classify(Profile::Autonomous, "github.com").unwrap(), DomainVerdict::Denied { .. }));
    }

    #[test]
    fn full_wildcard_admits_all() {
        let a = NetworkEgressDomainAllowlist::canonical();
        let v = a.classify(Profile::Experimental, "anywhere.example").unwrap();
        match v {
            DomainVerdict::Allowed { matched } => assert_eq!(matched, "*"),
            _ => panic!(),
        }
    }

    #[test]
    fn empty_host_rejected() {
        let a = NetworkEgressDomainAllowlist::canonical();
        assert!(matches!(a.classify(Profile::Production, "").unwrap_err(), DomainError::EmptyHost));
    }

    #[test]
    fn private_empty_set_denies_all() {
        let a = NetworkEgressDomainAllowlist::canonical();
        assert!(matches!(a.classify(Profile::Private, "api.anthropic.com").unwrap(), DomainVerdict::Denied { .. }));
    }

    #[test]
    fn case_insensitive_match() {
        let a = NetworkEgressDomainAllowlist::canonical();
        assert!(matches!(a.classify(Profile::Production, "API.Anthropic.COM").unwrap(), DomainVerdict::Allowed { .. }));
    }

    #[test]
    fn unconfigured_profile() {
        let mut a = NetworkEgressDomainAllowlist::canonical();
        a.profiles.clear();
        assert!(matches!(a.classify(Profile::Production, "x").unwrap(), DomainVerdict::Unconfigured));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut a = NetworkEgressDomainAllowlist::canonical();
        a.schema_version = "9.9.9".into();
        assert!(matches!(a.validate().unwrap_err(), DomainError::SchemaMismatch));
    }

    #[test]
    fn allowlist_serde_roundtrip() {
        let a = NetworkEgressDomainAllowlist::canonical();
        let j = serde_json::to_string(&a).unwrap();
        let back: NetworkEgressDomainAllowlist = serde_json::from_str(&j).unwrap();
        assert_eq!(a, back);
    }
}
