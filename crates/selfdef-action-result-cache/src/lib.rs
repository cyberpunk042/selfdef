//! `selfdef-action-result-cache` — short-lived deterministic-result cache.
//!
//! `put(action_hash, result, ts, ttl_ms)` stores a result.
//! `get(action_hash, now_ms)` returns:
//!   * `Hit { result, age_ms }` — stored, within TTL.
//!   * `Stale { age_ms, ttl_ms }` — stored, past TTL.
//!   * `Miss` — not stored.
//!
//! `rotate(now_ms)` drops entries past their TTL.
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
    /// Cached result.
    pub result: String,
    /// Stored at.
    pub stored_at_ms: u64,
    /// TTL.
    pub ttl_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionResultCache {
    /// Schema version.
    pub schema_version: String,
    /// action_hash → entry.
    pub entries: BTreeMap<u64, Entry>,
}

/// Verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum GetVerdict {
    /// Hit.
    Hit {
        /// result.
        result: String,
        /// age.
        age_ms: u64,
    },
    /// Stale.
    Stale {
        /// age.
        age_ms: u64,
        /// ttl.
        ttl_ms: u64,
    },
    /// Miss.
    Miss,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CacheError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty result.
    #[error("result empty")]
    EmptyResult,
    /// TTL zero.
    #[error("ttl_ms must be > 0")]
    ZeroTtl,
}

impl ActionResultCache {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            entries: BTreeMap::new(),
        }
    }

    /// Put.
    pub fn put(&mut self, action_hash: u64, result: &str, ts_ms: u64, ttl_ms: u64) -> Result<(), CacheError> {
        if result.is_empty() { return Err(CacheError::EmptyResult); }
        if ttl_ms == 0 { return Err(CacheError::ZeroTtl); }
        self.entries.insert(action_hash, Entry {
            result: result.into(),
            stored_at_ms: ts_ms,
            ttl_ms,
        });
        Ok(())
    }

    /// Get.
    pub fn get(&self, action_hash: u64, now_ms: u64) -> GetVerdict {
        let e = match self.entries.get(&action_hash) {
            Some(e) => e,
            None => return GetVerdict::Miss,
        };
        let age = now_ms.saturating_sub(e.stored_at_ms);
        if age <= e.ttl_ms {
            GetVerdict::Hit { result: e.result.clone(), age_ms: age }
        } else {
            GetVerdict::Stale { age_ms: age, ttl_ms: e.ttl_ms }
        }
    }

    /// Drop stale entries.
    pub fn rotate(&mut self, now_ms: u64) {
        self.entries.retain(|_, e| now_ms.saturating_sub(e.stored_at_ms) <= e.ttl_ms);
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CacheError> {
        if self.schema_version != SCHEMA_VERSION { return Err(CacheError::SchemaMismatch); }
        for e in self.entries.values() {
            if e.result.is_empty() { return Err(CacheError::EmptyResult); }
            if e.ttl_ms == 0 { return Err(CacheError::ZeroTtl); }
        }
        Ok(())
    }
}

impl Default for ActionResultCache {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn miss_when_empty() {
        let c = ActionResultCache::new();
        assert_eq!(c.get(0xabc, 0), GetVerdict::Miss);
    }

    #[test]
    fn hit_within_ttl() {
        let mut c = ActionResultCache::new();
        c.put(0xabc, "ok", 0, 1000).unwrap();
        match c.get(0xabc, 500) {
            GetVerdict::Hit { result, age_ms } => {
                assert_eq!(result, "ok");
                assert_eq!(age_ms, 500);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn stale_past_ttl() {
        let mut c = ActionResultCache::new();
        c.put(0xabc, "ok", 0, 1000).unwrap();
        match c.get(0xabc, 5000) {
            GetVerdict::Stale { age_ms, ttl_ms } => {
                assert_eq!(age_ms, 5000);
                assert_eq!(ttl_ms, 1000);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn rotate_drops_stale() {
        let mut c = ActionResultCache::new();
        c.put(0xabc, "ok", 0, 1000).unwrap();
        c.rotate(5000);
        assert_eq!(c.get(0xabc, 6000), GetVerdict::Miss);
    }

    #[test]
    fn empty_result_rejected() {
        let mut c = ActionResultCache::new();
        assert!(matches!(c.put(0xabc, "", 0, 1000).unwrap_err(), CacheError::EmptyResult));
    }

    #[test]
    fn zero_ttl_rejected() {
        let mut c = ActionResultCache::new();
        assert!(matches!(c.put(0xabc, "ok", 0, 0).unwrap_err(), CacheError::ZeroTtl));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = ActionResultCache::new();
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), CacheError::SchemaMismatch));
    }

    #[test]
    fn cache_serde_roundtrip() {
        let mut c = ActionResultCache::new();
        c.put(0xabc, "ok", 0, 1000).unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: ActionResultCache = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
