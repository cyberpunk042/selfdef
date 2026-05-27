//! `selfdef-dns-egress-policy` — DNS-name egress authority.
//!
//! Allow + Deny + NeverResolve lists with wildcard subdomain
//! support (`*.example.com` matches `a.example.com` and
//! `b.c.example.com` but not `example.com` itself). Precedence:
//! NeverResolve > Deny > Allow > implicit-deny.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Decision with the rule that matched.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DnsDecision {
    /// Allow; carries matched allow rule.
    Allow {
        /// allow rule.
        rule: String,
    },
    /// Deny by deny-list.
    DenyByDeny {
        /// deny rule.
        rule: String,
    },
    /// Deny by never-resolve.
    DenyByNever {
        /// never rule.
        rule: String,
    },
    /// Deny by no match.
    DenyImplicit,
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsEgressPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Allow patterns (exact host or `*.suffix`).
    pub allow: Vec<String>,
    /// Deny patterns.
    pub deny: Vec<String>,
    /// Never-resolve patterns.
    pub never_resolve: Vec<String>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DnsEgressError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty pattern.
    #[error("empty pattern in {0}")]
    EmptyPattern(String),
    /// Bad pattern (uppercase / whitespace / illegal char).
    #[error("invalid pattern {0:?}")]
    InvalidPattern(String),
}

impl DnsEgressPolicy {
    /// New empty.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            allow: Vec::new(),
            deny: Vec::new(),
            never_resolve: Vec::new(),
        }
    }

    /// Canonical: allow nothing by default, but always deny known
    /// exfil-friendly hosts (transfer.sh, pastebin.com, file.io).
    pub fn canonical() -> Self {
        let mut p = Self::new();
        p.never_resolve.push("transfer.sh".into());
        p.never_resolve.push("*.transfer.sh".into());
        p.never_resolve.push("pastebin.com".into());
        p.never_resolve.push("*.pastebin.com".into());
        p.never_resolve.push("file.io".into());
        p.never_resolve.push("*.file.io".into());
        p
    }

    /// Decide a single hostname.
    pub fn decide(&self, host: &str) -> DnsDecision {
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if h.is_empty() {
            return DnsDecision::DenyImplicit;
        }
        if let Some(r) = self.never_resolve.iter().find(|p| pattern_match(p, &h)) {
            return DnsDecision::DenyByNever { rule: r.clone() };
        }
        if let Some(r) = self.deny.iter().find(|p| pattern_match(p, &h)) {
            return DnsDecision::DenyByDeny { rule: r.clone() };
        }
        if let Some(r) = self.allow.iter().find(|p| pattern_match(p, &h)) {
            return DnsDecision::Allow { rule: r.clone() };
        }
        DnsDecision::DenyImplicit
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DnsEgressError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(DnsEgressError::SchemaMismatch);
        }
        for (sec, list) in [
            ("allow", &self.allow),
            ("deny", &self.deny),
            ("never_resolve", &self.never_resolve),
        ] {
            for p in list {
                if p.is_empty() {
                    return Err(DnsEgressError::EmptyPattern(sec.into()));
                }
                if !valid_pattern(p) {
                    return Err(DnsEgressError::InvalidPattern(p.clone()));
                }
            }
        }
        Ok(())
    }
}

fn valid_pattern(p: &str) -> bool {
    if p == "*" {
        return false;
    } // bare * disallowed
    // Allow `*.suffix.tld` or exact host.
    if let Some(rest) = p.strip_prefix("*.") {
        !rest.is_empty() && rest.chars().all(is_host_char)
    } else {
        !p.is_empty() && p.chars().all(is_host_char)
    }
}

fn is_host_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '.'
}

fn pattern_match(p: &str, host: &str) -> bool {
    if let Some(suffix) = p.strip_prefix("*.") {
        // Match any host whose suffix is `.suffix` (not the suffix itself).
        if let Some(stripped) = host.strip_suffix(suffix) {
            // Must end with ".suffix" (i.e., the char before must be a dot).
            return stripped.ends_with('.') && stripped.len() > 1;
        }
        false
    } else {
        p.eq_ignore_ascii_case(host)
    }
}

impl Default for DnsEgressPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_denies_implicitly() {
        let p = DnsEgressPolicy::new();
        assert!(matches!(p.decide("example.com"), DnsDecision::DenyImplicit));
    }

    #[test]
    fn allow_exact() {
        let mut p = DnsEgressPolicy::new();
        p.allow.push("example.com".into());
        assert!(matches!(p.decide("example.com"), DnsDecision::Allow { .. }));
        assert!(matches!(
            p.decide("a.example.com"),
            DnsDecision::DenyImplicit
        ));
    }

    #[test]
    fn allow_wildcard_subdomain() {
        let mut p = DnsEgressPolicy::new();
        p.allow.push("*.example.com".into());
        assert!(matches!(
            p.decide("a.example.com"),
            DnsDecision::Allow { .. }
        ));
        assert!(matches!(
            p.decide("a.b.example.com"),
            DnsDecision::Allow { .. }
        ));
        // Wildcard does NOT match the bare base.
        assert!(matches!(p.decide("example.com"), DnsDecision::DenyImplicit));
    }

    #[test]
    fn deny_overrides_allow() {
        let mut p = DnsEgressPolicy::new();
        p.allow.push("*.example.com".into());
        p.deny.push("evil.example.com".into());
        assert!(matches!(
            p.decide("evil.example.com"),
            DnsDecision::DenyByDeny { .. }
        ));
    }

    #[test]
    fn never_overrides_deny() {
        let mut p = DnsEgressPolicy::new();
        p.allow.push("*.example.com".into());
        p.deny.push("evil.example.com".into());
        p.never_resolve.push("*.example.com".into());
        let d = p.decide("evil.example.com");
        assert!(matches!(d, DnsDecision::DenyByNever { .. }));
    }

    #[test]
    fn canonical_blocks_exfil_hosts() {
        let p = DnsEgressPolicy::canonical();
        assert!(matches!(
            p.decide("transfer.sh"),
            DnsDecision::DenyByNever { .. }
        ));
        assert!(matches!(
            p.decide("foo.pastebin.com"),
            DnsDecision::DenyByNever { .. }
        ));
    }

    #[test]
    fn case_insensitive_host() {
        let mut p = DnsEgressPolicy::new();
        p.allow.push("example.com".into());
        assert!(matches!(p.decide("EXAMPLE.COM"), DnsDecision::Allow { .. }));
    }

    #[test]
    fn trailing_dot_normalized() {
        let mut p = DnsEgressPolicy::new();
        p.allow.push("example.com".into());
        assert!(matches!(
            p.decide("example.com."),
            DnsDecision::Allow { .. }
        ));
    }

    #[test]
    fn empty_host_denied() {
        assert!(matches!(
            DnsEgressPolicy::new().decide(""),
            DnsDecision::DenyImplicit
        ));
    }

    #[test]
    fn empty_pattern_rejected_on_validate() {
        let mut p = DnsEgressPolicy::new();
        p.allow.push(String::new());
        assert!(matches!(
            p.validate().unwrap_err(),
            DnsEgressError::EmptyPattern(_)
        ));
    }

    #[test]
    fn bare_star_rejected_on_validate() {
        let mut p = DnsEgressPolicy::new();
        p.allow.push("*".into());
        assert!(matches!(
            p.validate().unwrap_err(),
            DnsEgressError::InvalidPattern(_)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = DnsEgressPolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            DnsEgressError::SchemaMismatch
        ));
    }

    #[test]
    fn decision_serde_kebab() {
        let d = DnsDecision::DenyByNever { rule: "x".into() };
        let j = serde_json::to_string(&d).unwrap();
        assert!(j.contains("\"kind\":\"deny-by-never\""));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = DnsEgressPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: DnsEgressPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
