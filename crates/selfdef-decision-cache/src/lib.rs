//! `selfdef-decision-cache` — recent-decision dedup.
//!
//! Sliding-window cache keyed by `(subject, action, resource, profile)`.
//! Value = `Outcome` + `inserted_at_ms`. Caller decides TTL.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_policy_decision::Outcome;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Cache entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheEntry {
    /// Outcome.
    pub outcome: Outcome,
    /// epoch-ms insertion timestamp.
    pub inserted_at_ms: u64,
}

/// Cache.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionCache {
    /// Schema version.
    pub schema_version: String,
    /// TTL in ms; 0 means never expire.
    pub ttl_ms: u32,
    /// Keyed by "subject|action|resource|profile" string.
    pub entries: HashMap<String, CacheEntry>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CacheError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty subject / action / resource / profile.
    #[error("missing key field: {0}")]
    MissingField(&'static str),
}

fn key(subject: &str, action: &str, resource: &str, profile: &str) -> String {
    format!("{subject}|{action}|{resource}|{profile}")
}

impl DecisionCache {
    /// New with TTL (ms).
    pub fn new(ttl_ms: u32) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            ttl_ms,
            entries: HashMap::new(),
        }
    }

    /// Insert.
    pub fn insert(
        &mut self,
        subject: &str, action: &str, resource: &str, profile: &str,
        outcome: Outcome, now_ms: u64,
    ) -> Result<(), CacheError> {
        if subject.is_empty() { return Err(CacheError::MissingField("subject")); }
        if action.is_empty() { return Err(CacheError::MissingField("action")); }
        if resource.is_empty() { return Err(CacheError::MissingField("resource")); }
        if profile.is_empty() { return Err(CacheError::MissingField("profile")); }
        let k = key(subject, action, resource, profile);
        self.entries.insert(k, CacheEntry { outcome, inserted_at_ms: now_ms });
        Ok(())
    }

    /// Look up; honors TTL.
    pub fn get(
        &self,
        subject: &str, action: &str, resource: &str, profile: &str,
        now_ms: u64,
    ) -> Option<Outcome> {
        let k = key(subject, action, resource, profile);
        let e = self.entries.get(&k)?;
        if self.ttl_ms == 0 || now_ms.saturating_sub(e.inserted_at_ms) < self.ttl_ms as u64 {
            Some(e.outcome)
        } else {
            None
        }
    }

    /// Prune expired entries.
    pub fn prune(&mut self, now_ms: u64) {
        if self.ttl_ms == 0 { return; }
        self.entries.retain(|_, e| now_ms.saturating_sub(e.inserted_at_ms) < self.ttl_ms as u64);
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize { self.entries.len() }

    /// Is empty.
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    /// Validate.
    pub fn validate(&self) -> Result<(), CacheError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CacheError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cache_validates() {
        DecisionCache::new(1000).validate().unwrap();
    }

    #[test]
    fn insert_and_lookup() {
        let mut c = DecisionCache::new(10_000);
        c.insert("alice", "fs.read", "/x", "careful", Outcome::Allow, 1_000).unwrap();
        assert_eq!(c.get("alice", "fs.read", "/x", "careful", 2_000), Some(Outcome::Allow));
    }

    #[test]
    fn ttl_expires_lookup() {
        let mut c = DecisionCache::new(500);
        c.insert("alice", "fs.read", "/x", "careful", Outcome::Allow, 1_000).unwrap();
        assert_eq!(c.get("alice", "fs.read", "/x", "careful", 2_000), None);
    }

    #[test]
    fn ttl_zero_never_expires() {
        let mut c = DecisionCache::new(0);
        c.insert("alice", "fs.read", "/x", "careful", Outcome::Allow, 0).unwrap();
        assert_eq!(c.get("alice", "fs.read", "/x", "careful", u64::MAX), Some(Outcome::Allow));
    }

    #[test]
    fn missing_field_rejected() {
        let mut c = DecisionCache::new(1000);
        assert!(matches!(c.insert("", "a", "r", "p", Outcome::Allow, 0).unwrap_err(),
            CacheError::MissingField("subject")));
    }

    #[test]
    fn distinct_keys_separate() {
        let mut c = DecisionCache::new(10_000);
        c.insert("a", "x", "/r", "careful", Outcome::Allow, 1_000).unwrap();
        c.insert("a", "x", "/r", "fast",    Outcome::Deny, 1_000).unwrap();
        assert_eq!(c.get("a", "x", "/r", "careful", 1_000), Some(Outcome::Allow));
        assert_eq!(c.get("a", "x", "/r", "fast",    1_000), Some(Outcome::Deny));
    }

    #[test]
    fn prune_drops_expired() {
        let mut c = DecisionCache::new(1000);
        c.insert("a", "x", "/r", "p", Outcome::Allow, 0).unwrap();
        c.insert("b", "x", "/r", "p", Outcome::Allow, 0).unwrap();
        c.prune(2000);
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = DecisionCache::new(1000);
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), CacheError::SchemaMismatch));
    }

    #[test]
    fn cache_serde_roundtrip() {
        let mut c = DecisionCache::new(1000);
        c.insert("a", "x", "/r", "p", Outcome::Allow, 0).unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: DecisionCache = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
