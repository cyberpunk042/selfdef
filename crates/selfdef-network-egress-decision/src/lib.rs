//! `selfdef-network-egress-decision` — per-egress allow/deny gate.
//!
//! Given a request (subject, destination, port), and a set of
//! allowlist patterns (exact host / suffix / CIDR), returns
//! `Outcome::Allow` / `Outcome::Deny` / `Outcome::Ask`.
//!
//! Pattern matching is literal (no regex): suffix patterns start with
//! ".", CIDR uses naive prefix match on the leading octet count.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_policy_decision::Outcome;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Allowlist entry pattern type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PatternKind {
    /// Exact hostname match.
    ExactHost,
    /// Domain suffix (".example.com" matches "a.example.com" and "x.y.example.com").
    DomainSuffix,
    /// CIDR (naive: "10.0.0.0/8" matches any 10.x.x.x).
    Cidr,
}

/// One allowlist entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllowlistEntry {
    /// Kind.
    pub kind: PatternKind,
    /// Pattern (non-empty).
    pub pattern: String,
    /// Operator-readable note.
    pub note: String,
}

/// Egress request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EgressRequest {
    /// Subject.
    pub subject: String,
    /// Destination host (FQDN or dotted-quad).
    pub destination: String,
    /// Port.
    pub port: u16,
}

/// Allowlist envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EgressAllowlist {
    /// Schema version.
    pub schema_version: String,
    /// Entries.
    pub entries: Vec<AllowlistEntry>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum EgressError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty pattern.
    #[error("allowlist entry pattern empty")]
    EmptyPattern,
    /// Domain suffix must start with '.'.
    #[error("domain-suffix pattern {0} must start with '.'")]
    BadDomainSuffix(String),
    /// CIDR pattern must contain '/'.
    #[error("cidr pattern {0} missing '/'")]
    BadCidr(String),
    /// Empty subject.
    #[error("request subject empty")]
    EmptySubject,
    /// Empty destination.
    #[error("request destination empty")]
    EmptyDestination,
}

fn matches(entry: &AllowlistEntry, dest: &str) -> bool {
    match entry.kind {
        PatternKind::ExactHost => entry.pattern == dest,
        PatternKind::DomainSuffix => {
            // pattern ".example.com" matches "a.example.com" and "example.com".
            if entry.pattern.starts_with('.') {
                let suffix = &entry.pattern[1..];
                dest == suffix || dest.ends_with(&entry.pattern)
            } else {
                false
            }
        }
        PatternKind::Cidr => {
            let Some((prefix, bits_s)) = entry.pattern.split_once('/') else { return false; };
            let Ok(bits) = bits_s.parse::<u32>() else { return false; };
            // Octets matched: bits / 8 (truncate).
            let octets_needed = (bits / 8) as usize;
            let prefix_parts: Vec<&str> = prefix.split('.').collect();
            let dest_parts: Vec<&str> = dest.split('.').collect();
            if prefix_parts.len() != 4 || dest_parts.len() != 4 {
                return false;
            }
            if octets_needed > 4 { return false; }
            prefix_parts[..octets_needed] == dest_parts[..octets_needed]
        }
    }
}

impl EgressAllowlist {
    /// New empty.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            entries: Vec::new(),
        }
    }

    /// Add an entry.
    pub fn add(&mut self, e: AllowlistEntry) -> Result<(), EgressError> {
        if e.pattern.is_empty() { return Err(EgressError::EmptyPattern); }
        match e.kind {
            PatternKind::DomainSuffix if !e.pattern.starts_with('.') => {
                return Err(EgressError::BadDomainSuffix(e.pattern));
            }
            PatternKind::Cidr if !e.pattern.contains('/') => {
                return Err(EgressError::BadCidr(e.pattern));
            }
            _ => {}
        }
        self.entries.push(e);
        Ok(())
    }

    /// Decide for an egress request.
    pub fn decide(&self, req: &EgressRequest) -> Result<Outcome, EgressError> {
        if req.subject.is_empty() { return Err(EgressError::EmptySubject); }
        if req.destination.is_empty() { return Err(EgressError::EmptyDestination); }
        for e in &self.entries {
            if matches(e, &req.destination) {
                return Ok(Outcome::Allow);
            }
        }
        // No match → Deny (operator must add allowlist entry first).
        Ok(Outcome::Deny)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), EgressError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(EgressError::SchemaMismatch);
        }
        for e in &self.entries {
            if e.pattern.is_empty() { return Err(EgressError::EmptyPattern); }
            match e.kind {
                PatternKind::DomainSuffix if !e.pattern.starts_with('.') => {
                    return Err(EgressError::BadDomainSuffix(e.pattern.clone()));
                }
                PatternKind::Cidr if !e.pattern.contains('/') => {
                    return Err(EgressError::BadCidr(e.pattern.clone()));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

impl Default for EgressAllowlist {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(kind: PatternKind, pat: &str) -> AllowlistEntry {
        AllowlistEntry { kind, pattern: pat.into(), note: String::new() }
    }

    fn req(dest: &str) -> EgressRequest {
        EgressRequest { subject: "op".into(), destination: dest.into(), port: 443 }
    }

    #[test]
    fn empty_allowlist_denies_everything() {
        let a = EgressAllowlist::new();
        assert_eq!(a.decide(&req("any.example.com")).unwrap(), Outcome::Deny);
    }

    #[test]
    fn exact_host_match() {
        let mut a = EgressAllowlist::new();
        a.add(e(PatternKind::ExactHost, "api.anthropic.com")).unwrap();
        assert_eq!(a.decide(&req("api.anthropic.com")).unwrap(), Outcome::Allow);
        assert_eq!(a.decide(&req("api.openai.com")).unwrap(), Outcome::Deny);
    }

    #[test]
    fn domain_suffix_match() {
        let mut a = EgressAllowlist::new();
        a.add(e(PatternKind::DomainSuffix, ".example.org")).unwrap();
        assert_eq!(a.decide(&req("a.example.org")).unwrap(), Outcome::Allow);
        assert_eq!(a.decide(&req("x.y.example.org")).unwrap(), Outcome::Allow);
        assert_eq!(a.decide(&req("example.org")).unwrap(), Outcome::Allow);
        assert_eq!(a.decide(&req("example.com")).unwrap(), Outcome::Deny);
    }

    #[test]
    fn domain_suffix_must_start_with_dot() {
        let mut a = EgressAllowlist::new();
        let err = a.add(e(PatternKind::DomainSuffix, "no-dot.com")).unwrap_err();
        assert!(matches!(err, EgressError::BadDomainSuffix(_)));
    }

    #[test]
    fn cidr_8_bit_match() {
        let mut a = EgressAllowlist::new();
        a.add(e(PatternKind::Cidr, "10.0.0.0/8")).unwrap();
        assert_eq!(a.decide(&req("10.1.2.3")).unwrap(), Outcome::Allow);
        assert_eq!(a.decide(&req("10.255.0.0")).unwrap(), Outcome::Allow);
        assert_eq!(a.decide(&req("11.0.0.0")).unwrap(), Outcome::Deny);
    }

    #[test]
    fn cidr_16_bit_match() {
        let mut a = EgressAllowlist::new();
        a.add(e(PatternKind::Cidr, "192.168.0.0/16")).unwrap();
        assert_eq!(a.decide(&req("192.168.1.1")).unwrap(), Outcome::Allow);
        assert_eq!(a.decide(&req("192.169.0.0")).unwrap(), Outcome::Deny);
    }

    #[test]
    fn cidr_must_contain_slash() {
        let mut a = EgressAllowlist::new();
        let err = a.add(e(PatternKind::Cidr, "10.0.0.0")).unwrap_err();
        assert!(matches!(err, EgressError::BadCidr(_)));
    }

    #[test]
    fn empty_pattern_rejected() {
        let mut a = EgressAllowlist::new();
        let err = a.add(e(PatternKind::ExactHost, "")).unwrap_err();
        assert!(matches!(err, EgressError::EmptyPattern));
    }

    #[test]
    fn empty_subject_rejected() {
        let a = EgressAllowlist::new();
        let mut r = req("a");
        r.subject = String::new();
        assert!(matches!(a.decide(&r).unwrap_err(), EgressError::EmptySubject));
    }

    #[test]
    fn empty_destination_rejected() {
        let a = EgressAllowlist::new();
        let mut r = req("a");
        r.destination = String::new();
        assert!(matches!(a.decide(&r).unwrap_err(), EgressError::EmptyDestination));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut a = EgressAllowlist::new();
        a.schema_version = "9.9.9".into();
        assert!(matches!(a.validate().unwrap_err(), EgressError::SchemaMismatch));
    }

    #[test]
    fn kind_serde_kebab() {
        assert_eq!(serde_json::to_string(&PatternKind::ExactHost).unwrap(), "\"exact-host\"");
        assert_eq!(serde_json::to_string(&PatternKind::DomainSuffix).unwrap(), "\"domain-suffix\"");
        assert_eq!(serde_json::to_string(&PatternKind::Cidr).unwrap(), "\"cidr\"");
    }

    #[test]
    fn allowlist_serde_roundtrip() {
        let mut a = EgressAllowlist::new();
        a.add(e(PatternKind::DomainSuffix, ".example.org")).unwrap();
        a.add(e(PatternKind::Cidr, "10.0.0.0/8")).unwrap();
        let j = serde_json::to_string(&a).unwrap();
        let back: EgressAllowlist = serde_json::from_str(&j).unwrap();
        assert_eq!(a, back);
    }
}
