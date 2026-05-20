//! `selfdef-denylist-store` — TTL'd denylist.
//!
//! Entry{key, reason, added_at_ms, expires_at_ms}. add(key, reason,
//! now, ttl_ms) inserts (expires_at = now + ttl, ttl=0 for permanent).
//! denied(key, now) true iff entry exists AND not expired. compact
//! prunes expired. reason(key) returns the audit string.
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
    /// Reason.
    pub reason: String,
    /// Added ts ms.
    pub added_at_ms: u64,
    /// Expires ts ms (0 = permanent).
    pub expires_at_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DenylistStore {
    /// Schema version.
    pub schema_version: String,
    /// key → entry.
    pub entries: BTreeMap<String, Entry>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DenyError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("key empty")]
    EmptyKey,
    /// Empty.
    #[error("reason empty")]
    EmptyReason,
    /// Unknown.
    #[error("unknown key: {0}")]
    Unknown(String),
}

impl DenylistStore {
    /// New.
    pub fn new() -> Self {
        Self { schema_version: SCHEMA_VERSION.into(), entries: BTreeMap::new() }
    }

    /// Add (ttl=0 means permanent).
    pub fn add(&mut self, key: &str, reason: &str, now_ms: u64, ttl_ms: u64) -> Result<(), DenyError> {
        if key.is_empty() { return Err(DenyError::EmptyKey); }
        if reason.is_empty() { return Err(DenyError::EmptyReason); }
        let expires_at_ms = if ttl_ms == 0 { 0 } else { now_ms.saturating_add(ttl_ms) };
        self.entries.insert(key.into(), Entry {
            reason: reason.into(),
            added_at_ms: now_ms,
            expires_at_ms,
        });
        Ok(())
    }

    /// Remove.
    pub fn remove(&mut self, key: &str) -> Result<(), DenyError> {
        self.entries.remove(key).map(|_| ()).ok_or_else(|| DenyError::Unknown(key.into()))
    }

    /// Is key denied at now_ms?
    pub fn denied(&self, key: &str, now_ms: u64) -> bool {
        match self.entries.get(key) {
            None => false,
            Some(e) => e.expires_at_ms == 0 || e.expires_at_ms > now_ms,
        }
    }

    /// Reason for a key (returns even if expired; consumer can check denied).
    pub fn reason(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(|e| e.reason.as_str())
    }

    /// Drop expired entries.
    pub fn compact(&mut self, now_ms: u64) {
        self.entries.retain(|_, e| e.expires_at_ms == 0 || e.expires_at_ms > now_ms);
    }

    /// Count live entries.
    pub fn live(&self, now_ms: u64) -> usize {
        self.entries.values()
            .filter(|e| e.expires_at_ms == 0 || e.expires_at_ms > now_ms)
            .count()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DenyError> {
        if self.schema_version != SCHEMA_VERSION { return Err(DenyError::SchemaMismatch); }
        for (k, e) in &self.entries {
            if k.is_empty() { return Err(DenyError::EmptyKey); }
            if e.reason.is_empty() { return Err(DenyError::EmptyReason); }
        }
        Ok(())
    }
}

impl Default for DenylistStore {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denied_within_ttl() {
        let mut s = DenylistStore::new();
        s.add("k", "bad ip", 0, 1000).unwrap();
        assert!(s.denied("k", 500));
        assert!(!s.denied("k", 1500));
    }

    #[test]
    fn permanent_never_expires() {
        let mut s = DenylistStore::new();
        s.add("k", "forever", 0, 0).unwrap();
        assert!(s.denied("k", u64::MAX));
    }

    #[test]
    fn reason_returns_audit_string() {
        let mut s = DenylistStore::new();
        s.add("k", "abuse", 0, 1000).unwrap();
        assert_eq!(s.reason("k"), Some("abuse"));
        assert_eq!(s.reason("missing"), None);
    }

    #[test]
    fn compact_prunes_expired() {
        let mut s = DenylistStore::new();
        s.add("a", "x", 0, 1000).unwrap();
        s.add("b", "y", 0, 5000).unwrap();
        s.compact(2000);
        assert!(!s.entries.contains_key("a"));
        assert!(s.entries.contains_key("b"));
    }

    #[test]
    fn remove_unknown_rejected() {
        let mut s = DenylistStore::new();
        assert!(matches!(s.remove("missing").unwrap_err(), DenyError::Unknown(_)));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut s = DenylistStore::new();
        assert!(matches!(s.add("", "x", 0, 0).unwrap_err(), DenyError::EmptyKey));
        assert!(matches!(s.add("k", "", 0, 0).unwrap_err(), DenyError::EmptyReason));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = DenylistStore::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), DenyError::SchemaMismatch));
    }

    #[test]
    fn deny_serde_roundtrip() {
        let mut s = DenylistStore::new();
        s.add("k", "x", 100, 5000).unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: DenylistStore = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
