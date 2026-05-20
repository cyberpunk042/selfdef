//! `selfdef-allowlist-store` — TTL'd allowlist with audit reason.
//!
//! Entry{reason, granted_by, granted_at_ms, expires_at_ms}.
//! grant(key, reason, granted_by, now, ttl_ms) inserts; ttl=0 is
//! permanent. allowed(key, now) true iff non-expired entry exists.
//! revoke removes. compact prunes expired. Counterpart to
//! selfdef-denylist-store — denylist denies by default + allowlist
//! permits explicit exemptions.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// Audit reason.
    pub reason: String,
    /// Granted-by signer.
    pub granted_by: String,
    /// Granted ts ms.
    pub granted_at_ms: u64,
    /// Expires ts ms (0 = permanent).
    pub expires_at_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllowlistStore {
    /// Schema version.
    pub schema_version: String,
    /// key → entry.
    pub entries: BTreeMap<String, Entry>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum AllowError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("key empty")]
    EmptyKey,
    /// Empty.
    #[error("reason empty")]
    EmptyReason,
    /// Empty.
    #[error("granted_by empty")]
    EmptyGrantedBy,
    /// Unknown.
    #[error("unknown key: {0}")]
    Unknown(String),
}

impl AllowlistStore {
    /// New.
    pub fn new() -> Self {
        Self { schema_version: SCHEMA_VERSION.into(), entries: BTreeMap::new() }
    }

    /// Grant.
    pub fn grant(&mut self, key: &str, reason: &str, granted_by: &str, now_ms: u64, ttl_ms: u64) -> Result<(), AllowError> {
        if key.is_empty() { return Err(AllowError::EmptyKey); }
        if reason.is_empty() { return Err(AllowError::EmptyReason); }
        if granted_by.is_empty() { return Err(AllowError::EmptyGrantedBy); }
        let expires_at_ms = if ttl_ms == 0 { 0 } else { now_ms.saturating_add(ttl_ms) };
        self.entries.insert(key.into(), Entry {
            reason: reason.into(),
            granted_by: granted_by.into(),
            granted_at_ms: now_ms,
            expires_at_ms,
        });
        Ok(())
    }

    /// Revoke.
    pub fn revoke(&mut self, key: &str) -> Result<(), AllowError> {
        self.entries.remove(key).map(|_| ()).ok_or_else(|| AllowError::Unknown(key.into()))
    }

    /// Allowed?
    pub fn allowed(&self, key: &str, now_ms: u64) -> bool {
        match self.entries.get(key) {
            None => false,
            Some(e) => e.expires_at_ms == 0 || e.expires_at_ms > now_ms,
        }
    }

    /// Audit reason (alive or expired).
    pub fn reason(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(|e| e.reason.as_str())
    }

    /// Drop expired entries.
    pub fn compact(&mut self, now_ms: u64) {
        self.entries.retain(|_, e| e.expires_at_ms == 0 || e.expires_at_ms > now_ms);
    }

    /// Live entry count.
    pub fn live(&self, now_ms: u64) -> usize {
        self.entries.values()
            .filter(|e| e.expires_at_ms == 0 || e.expires_at_ms > now_ms)
            .count()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), AllowError> {
        if self.schema_version != SCHEMA_VERSION { return Err(AllowError::SchemaMismatch); }
        for (k, e) in &self.entries {
            if k.is_empty() { return Err(AllowError::EmptyKey); }
            if e.reason.is_empty() { return Err(AllowError::EmptyReason); }
            if e.granted_by.is_empty() { return Err(AllowError::EmptyGrantedBy); }
        }
        Ok(())
    }
}

impl Default for AllowlistStore {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_then_allowed() {
        let mut s = AllowlistStore::new();
        s.grant("k", "vip", "admin", 0, 1000).unwrap();
        assert!(s.allowed("k", 500));
    }

    #[test]
    fn expires_after_ttl() {
        let mut s = AllowlistStore::new();
        s.grant("k", "vip", "admin", 0, 1000).unwrap();
        assert!(!s.allowed("k", 2000));
    }

    #[test]
    fn permanent_never_expires() {
        let mut s = AllowlistStore::new();
        s.grant("k", "vip", "admin", 0, 0).unwrap();
        assert!(s.allowed("k", u64::MAX));
    }

    #[test]
    fn revoke_removes() {
        let mut s = AllowlistStore::new();
        s.grant("k", "vip", "admin", 0, 1000).unwrap();
        s.revoke("k").unwrap();
        assert!(!s.allowed("k", 500));
        assert!(matches!(s.revoke("k").unwrap_err(), AllowError::Unknown(_)));
    }

    #[test]
    fn reason_returns_audit_string() {
        let mut s = AllowlistStore::new();
        s.grant("k", "ticket-42", "admin", 0, 1000).unwrap();
        assert_eq!(s.reason("k"), Some("ticket-42"));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut s = AllowlistStore::new();
        assert!(matches!(s.grant("", "x", "y", 0, 0).unwrap_err(), AllowError::EmptyKey));
        assert!(matches!(s.grant("k", "", "y", 0, 0).unwrap_err(), AllowError::EmptyReason));
        assert!(matches!(s.grant("k", "x", "", 0, 0).unwrap_err(), AllowError::EmptyGrantedBy));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = AllowlistStore::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), AllowError::SchemaMismatch));
    }

    #[test]
    fn allow_serde_roundtrip() {
        let mut s = AllowlistStore::new();
        s.grant("k", "x", "y", 10, 100).unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: AllowlistStore = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
