//! `selfdef-network-rule-pack` — outbound allow/deny rule pack.
//!
//! 2 rule classes: `allow` and `deny`. Deny takes precedence: if a
//! destination matches any deny pattern it is rejected even if an
//! allow pattern also matches. If nothing matches, the default is
//! Deny (closed-default).
//!
//! Patterns use `Pattern::Fqdn` (suffix) or `Pattern::Cidr` from
//! `selfdef-pattern-match-engine`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_pattern_match_engine::Pattern;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// Allowed.
    Allow,
    /// Denied by an explicit deny rule.
    DenyExplicit,
    /// Denied by closed-default (no allow matched).
    DenyDefault,
}

/// Rule pack envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkRulePack {
    /// Schema version.
    pub schema_version: String,
    /// Allowlist patterns.
    pub allow: Vec<Pattern>,
    /// Denylist patterns (take precedence).
    pub deny: Vec<Pattern>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RulePackError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Pattern body empty.
    #[error("rule has empty pattern body")]
    EmptyPattern,
    /// Pattern unsupported for network (only Fqdn / Cidr allowed).
    #[error("network rule uses unsupported pattern kind")]
    UnsupportedPattern,
}

fn pattern_ok_for_network(p: &Pattern) -> bool {
    matches!(p, Pattern::Fqdn(_) | Pattern::Cidr(_))
}

impl NetworkRulePack {
    /// New empty pack.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }

    /// Add an allow pattern.
    pub fn add_allow(&mut self, p: Pattern) -> Result<(), RulePackError> {
        if !pattern_ok_for_network(&p) {
            return Err(RulePackError::UnsupportedPattern);
        }
        p.validate().map_err(|_| RulePackError::EmptyPattern)?;
        self.allow.push(p);
        Ok(())
    }

    /// Add a deny pattern.
    pub fn add_deny(&mut self, p: Pattern) -> Result<(), RulePackError> {
        if !pattern_ok_for_network(&p) {
            return Err(RulePackError::UnsupportedPattern);
        }
        p.validate().map_err(|_| RulePackError::EmptyPattern)?;
        self.deny.push(p);
        Ok(())
    }

    /// Decide a destination.
    pub fn decide(&self, destination: &str) -> Verdict {
        if self.deny.iter().any(|p| p.matches(destination)) {
            return Verdict::DenyExplicit;
        }
        if self.allow.iter().any(|p| p.matches(destination)) {
            return Verdict::Allow;
        }
        Verdict::DenyDefault
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RulePackError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RulePackError::SchemaMismatch);
        }
        for p in self.allow.iter().chain(self.deny.iter()) {
            if !pattern_ok_for_network(p) {
                return Err(RulePackError::UnsupportedPattern);
            }
            p.validate().map_err(|_| RulePackError::EmptyPattern)?;
        }
        Ok(())
    }
}

impl Default for NetworkRulePack {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_pack_default_denies() {
        let p = NetworkRulePack::new();
        assert_eq!(p.decide("api.anthropic.com"), Verdict::DenyDefault);
    }

    #[test]
    fn allow_fqdn_suffix() {
        let mut p = NetworkRulePack::new();
        p.add_allow(Pattern::Fqdn(".anthropic.com".into())).unwrap();
        assert_eq!(p.decide("api.anthropic.com"), Verdict::Allow);
        assert_eq!(p.decide("api.openai.com"), Verdict::DenyDefault);
    }

    #[test]
    fn deny_takes_precedence_over_allow() {
        let mut p = NetworkRulePack::new();
        p.add_allow(Pattern::Fqdn(".anthropic.com".into())).unwrap();
        p.add_deny(Pattern::Fqdn(".evil.anthropic.com".into()))
            .unwrap();
        assert_eq!(p.decide("api.anthropic.com"), Verdict::Allow);
        assert_eq!(p.decide("a.evil.anthropic.com"), Verdict::DenyExplicit);
    }

    #[test]
    fn cidr_allow() {
        let mut p = NetworkRulePack::new();
        p.add_allow(Pattern::Cidr("10.0.0.0/8".into())).unwrap();
        assert_eq!(p.decide("10.1.2.3"), Verdict::Allow);
        assert_eq!(p.decide("11.0.0.0"), Verdict::DenyDefault);
    }

    #[test]
    fn unsupported_pattern_rejected() {
        let mut p = NetworkRulePack::new();
        let err = p.add_allow(Pattern::PathGlob("/etc/x".into())).unwrap_err();
        assert!(matches!(err, RulePackError::UnsupportedPattern));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = NetworkRulePack::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            RulePackError::SchemaMismatch
        ));
    }

    #[test]
    fn verdict_serde_kebab() {
        assert_eq!(serde_json::to_string(&Verdict::Allow).unwrap(), "\"allow\"");
        assert_eq!(
            serde_json::to_string(&Verdict::DenyExplicit).unwrap(),
            "\"deny-explicit\""
        );
        assert_eq!(
            serde_json::to_string(&Verdict::DenyDefault).unwrap(),
            "\"deny-default\""
        );
    }

    #[test]
    fn pack_serde_roundtrip() {
        let mut p = NetworkRulePack::new();
        p.add_allow(Pattern::Fqdn(".example.org".into())).unwrap();
        p.add_deny(Pattern::Cidr("192.168.0.0/16".into())).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: NetworkRulePack = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
