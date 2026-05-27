//! `selfdef-ttl-table` — key→string with per-entry TTL.
//!
//! Entry{value, expires_at_ms}. insert(key, value, now, ttl_ms)
//! sets expires_at = now + ttl. get(key, now) returns value iff
//! not expired (lazy). sweep(now) removes expired entries
//! eagerly and returns the count removed. touch(key, now,
//! ttl_ms) refreshes expiry. Pure data.
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
    /// Value.
    pub value: String,
    /// Absolute expiry ts ms.
    pub expires_at_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TtlTable {
    /// Schema version.
    pub schema_version: String,
    /// key → entry.
    pub entries: BTreeMap<String, Entry>,
    /// Inserts.
    pub inserts: u64,
    /// Expired removals (lazy + sweep combined).
    pub expired: u64,
    /// Hits on get.
    pub hits: u64,
    /// Misses on get (including expired).
    pub misses: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum TtlError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("key empty")]
    EmptyKey,
    /// Zero ttl.
    #[error("ttl_ms must be >= 1")]
    ZeroTtl,
}

impl TtlTable {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            entries: BTreeMap::new(),
            inserts: 0,
            expired: 0,
            hits: 0,
            misses: 0,
        }
    }

    /// Insert (or replace).
    pub fn insert(
        &mut self,
        key: &str,
        value: &str,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<(), TtlError> {
        if key.is_empty() {
            return Err(TtlError::EmptyKey);
        }
        if ttl_ms == 0 {
            return Err(TtlError::ZeroTtl);
        }
        let expires_at_ms = now_ms.saturating_add(ttl_ms);
        self.entries.insert(
            key.into(),
            Entry {
                value: value.into(),
                expires_at_ms,
            },
        );
        self.inserts = self.inserts.saturating_add(1);
        Ok(())
    }

    /// Get value if not expired (lazy expiry: expired entry is removed).
    pub fn get(&mut self, key: &str, now_ms: u64) -> Option<String> {
        let expired = match self.entries.get(key) {
            Some(e) if e.expires_at_ms <= now_ms => true,
            Some(_) => false,
            None => {
                self.misses = self.misses.saturating_add(1);
                return None;
            }
        };
        if expired {
            self.entries.remove(key);
            self.expired = self.expired.saturating_add(1);
            self.misses = self.misses.saturating_add(1);
            return None;
        }
        let v = self.entries.get(key).unwrap().value.clone();
        self.hits = self.hits.saturating_add(1);
        Some(v)
    }

    /// Touch (refresh) expiry.
    pub fn touch(&mut self, key: &str, now_ms: u64, ttl_ms: u64) -> Result<bool, TtlError> {
        if ttl_ms == 0 {
            return Err(TtlError::ZeroTtl);
        }
        if let Some(e) = self.entries.get_mut(key) {
            e.expires_at_ms = now_ms.saturating_add(ttl_ms);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Eagerly remove expired entries; returns count removed.
    pub fn sweep(&mut self, now_ms: u64) -> u32 {
        let stale: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, e)| e.expires_at_ms <= now_ms)
            .map(|(k, _)| k.clone())
            .collect();
        let n = stale.len() as u32;
        for k in stale {
            self.entries.remove(&k);
        }
        self.expired = self.expired.saturating_add(n as u64);
        n
    }

    /// Count.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), TtlError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(TtlError::SchemaMismatch);
        }
        for k in self.entries.keys() {
            if k.is_empty() {
                return Err(TtlError::EmptyKey);
            }
        }
        Ok(())
    }
}

impl Default for TtlTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_get_hits() {
        let mut t = TtlTable::new();
        t.insert("a", "v", 0, 1000).unwrap();
        assert_eq!(t.get("a", 500), Some("v".into()));
        assert_eq!(t.hits, 1);
    }

    #[test]
    fn expired_get_misses() {
        let mut t = TtlTable::new();
        t.insert("a", "v", 0, 1000).unwrap();
        assert_eq!(t.get("a", 1500), None);
        assert_eq!(t.expired, 1);
        assert_eq!(t.misses, 1);
    }

    #[test]
    fn unknown_get_misses() {
        let mut t = TtlTable::new();
        assert_eq!(t.get("nope", 100), None);
        assert_eq!(t.misses, 1);
    }

    #[test]
    fn touch_extends_ttl() {
        let mut t = TtlTable::new();
        t.insert("a", "v", 0, 1000).unwrap();
        assert!(t.touch("a", 500, 1000).unwrap());
        // Now expires at 1500.
        assert!(t.get("a", 1400).is_some());
        assert!(t.get("a", 1500).is_none());
    }

    #[test]
    fn sweep_removes_expired() {
        let mut t = TtlTable::new();
        t.insert("a", "v", 0, 100).unwrap();
        t.insert("b", "v", 0, 1000).unwrap();
        let n = t.sweep(500);
        assert_eq!(n, 1);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn replace_resets_expiry() {
        let mut t = TtlTable::new();
        t.insert("a", "v1", 0, 100).unwrap();
        t.insert("a", "v2", 500, 1000).unwrap();
        assert_eq!(t.get("a", 1000), Some("v2".into()));
    }

    #[test]
    fn bad_inputs_rejected() {
        let mut t = TtlTable::new();
        assert!(matches!(
            t.insert("", "v", 0, 100).unwrap_err(),
            TtlError::EmptyKey
        ));
        assert!(matches!(
            t.insert("k", "v", 0, 0).unwrap_err(),
            TtlError::ZeroTtl
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = TtlTable::new();
        t.schema_version = "9.9.9".into();
        assert!(matches!(
            t.validate().unwrap_err(),
            TtlError::SchemaMismatch
        ));
    }

    #[test]
    fn table_serde_roundtrip() {
        let mut t = TtlTable::new();
        t.insert("a", "v", 0, 1000).unwrap();
        let j = serde_json::to_string(&t).unwrap();
        let back: TtlTable = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
