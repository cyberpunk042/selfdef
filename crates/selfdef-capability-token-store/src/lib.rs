//! `selfdef-capability-token-store` — issued capability tokens.
//!
//! Token{id, holder, scopes:BTreeSet, expires_at_ms, revoked}.
//! issue/revoke; check(id, scope, now) returns
//! Ok/Expired/Revoked/Unknown/MissingScope.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Token {
    /// Id.
    pub id: String,
    /// Holder actor.
    pub holder: String,
    /// Scopes.
    pub scopes: BTreeSet<String>,
    /// Expires.
    pub expires_at_ms: u64,
    /// Revoked.
    pub revoked: bool,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityTokenStore {
    /// Schema version.
    pub schema_version: String,
    /// id → token.
    pub tokens: BTreeMap<String, Token>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CheckVerdict {
    /// OK.
    Ok,
    /// Expired.
    Expired,
    /// Revoked.
    Revoked,
    /// Unknown.
    Unknown,
    /// Missing scope.
    MissingScope,
}

/// Errors.
#[derive(Debug, Error)]
pub enum TokenError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("id empty")]
    EmptyId,
    /// Empty.
    #[error("holder empty")]
    EmptyHolder,
    /// Empty.
    #[error("scope empty")]
    EmptyScope,
    /// Duplicate.
    #[error("duplicate token id: {0}")]
    DuplicateId(String),
}

impl CapabilityTokenStore {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            tokens: BTreeMap::new(),
        }
    }

    /// Issue.
    pub fn issue(&mut self, id: &str, holder: &str, scopes: &[&str], expires_at_ms: u64) -> Result<(), TokenError> {
        if id.is_empty() { return Err(TokenError::EmptyId); }
        if holder.is_empty() { return Err(TokenError::EmptyHolder); }
        if self.tokens.contains_key(id) {
            return Err(TokenError::DuplicateId(id.into()));
        }
        let mut set = BTreeSet::new();
        for s in scopes {
            if s.is_empty() { return Err(TokenError::EmptyScope); }
            set.insert((*s).into());
        }
        self.tokens.insert(id.into(), Token {
            id: id.into(),
            holder: holder.into(),
            scopes: set,
            expires_at_ms,
            revoked: false,
        });
        Ok(())
    }

    /// Revoke.
    pub fn revoke(&mut self, id: &str) -> bool {
        if let Some(t) = self.tokens.get_mut(id) {
            t.revoked = true;
            true
        } else { false }
    }

    /// Check.
    pub fn check(&self, id: &str, scope: &str, now_ms: u64) -> CheckVerdict {
        let Some(t) = self.tokens.get(id) else { return CheckVerdict::Unknown; };
        if t.revoked { return CheckVerdict::Revoked; }
        if now_ms >= t.expires_at_ms { return CheckVerdict::Expired; }
        if !t.scopes.contains(scope) { return CheckVerdict::MissingScope; }
        CheckVerdict::Ok
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), TokenError> {
        if self.schema_version != SCHEMA_VERSION { return Err(TokenError::SchemaMismatch); }
        for (id, t) in &self.tokens {
            if id.is_empty() { return Err(TokenError::EmptyId); }
            if t.holder.is_empty() { return Err(TokenError::EmptyHolder); }
            for s in &t.scopes {
                if s.is_empty() { return Err(TokenError::EmptyScope); }
            }
        }
        Ok(())
    }
}

impl Default for CapabilityTokenStore {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_when_valid() {
        let mut s = CapabilityTokenStore::new();
        s.issue("t1", "alice", &["read", "write"], 1000).unwrap();
        assert_eq!(s.check("t1", "read", 500), CheckVerdict::Ok);
    }

    #[test]
    fn missing_scope() {
        let mut s = CapabilityTokenStore::new();
        s.issue("t1", "alice", &["read"], 1000).unwrap();
        assert_eq!(s.check("t1", "write", 500), CheckVerdict::MissingScope);
    }

    #[test]
    fn expired() {
        let mut s = CapabilityTokenStore::new();
        s.issue("t1", "alice", &["read"], 1000).unwrap();
        assert_eq!(s.check("t1", "read", 1500), CheckVerdict::Expired);
    }

    #[test]
    fn revoked_blocks() {
        let mut s = CapabilityTokenStore::new();
        s.issue("t1", "alice", &["read"], 1000).unwrap();
        s.revoke("t1");
        assert_eq!(s.check("t1", "read", 500), CheckVerdict::Revoked);
    }

    #[test]
    fn unknown() {
        let s = CapabilityTokenStore::new();
        assert_eq!(s.check("nope", "x", 0), CheckVerdict::Unknown);
    }

    #[test]
    fn duplicate_rejected() {
        let mut s = CapabilityTokenStore::new();
        s.issue("t1", "alice", &["r"], 1000).unwrap();
        assert!(matches!(s.issue("t1", "bob", &["r"], 1000).unwrap_err(), TokenError::DuplicateId(_)));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut s = CapabilityTokenStore::new();
        assert!(matches!(s.issue("", "h", &[], 1).unwrap_err(), TokenError::EmptyId));
        assert!(matches!(s.issue("t", "", &[], 1).unwrap_err(), TokenError::EmptyHolder));
        assert!(matches!(s.issue("t", "h", &[""], 1).unwrap_err(), TokenError::EmptyScope));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = CapabilityTokenStore::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), TokenError::SchemaMismatch));
    }

    #[test]
    fn token_serde_roundtrip() {
        let mut s = CapabilityTokenStore::new();
        s.issue("t1", "alice", &["read"], 1000).unwrap();
        s.revoke("t1");
        let j = serde_json::to_string(&s).unwrap();
        let back: CapabilityTokenStore = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
