//! `selfdef-content-hash-cache` — content→hash dedup cache.
//!
//! Each Entry{hash, first_seen_at_ms, seen_count, last_seen_at_ms}.
//! observe(content, now) returns Existing{hash, seen_count}/New{hash}.
//! Hash via FNV-1a-64.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// Hash.
    pub hash: u64,
    /// First seen.
    pub first_seen_at_ms: u64,
    /// Last seen.
    pub last_seen_at_ms: u64,
    /// Seen count.
    pub seen_count: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentHashCache {
    /// Schema version.
    pub schema_version: String,
    /// hash → entry.
    pub entries: BTreeMap<u64, Entry>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ObserveVerdict {
    /// New (first observation).
    New {
        /// hash.
        hash: u64,
    },
    /// Existing (duplicate).
    Existing {
        /// hash.
        hash: u64,
        /// seen count.
        seen_count: u64,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum CacheError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

impl ContentHashCache {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            entries: BTreeMap::new(),
        }
    }

    /// Observe.
    pub fn observe(&mut self, content: &[u8], now_ms: u64) -> ObserveVerdict {
        let hash = fnv1a_64(content);
        if let Some(e) = self.entries.get_mut(&hash) {
            e.seen_count = e.seen_count.saturating_add(1);
            e.last_seen_at_ms = now_ms;
            ObserveVerdict::Existing { hash, seen_count: e.seen_count }
        } else {
            self.entries.insert(hash, Entry {
                hash,
                first_seen_at_ms: now_ms,
                last_seen_at_ms: now_ms,
                seen_count: 1,
            });
            ObserveVerdict::New { hash }
        }
    }

    /// Prune entries older than max_age (by last_seen).
    pub fn prune(&mut self, now_ms: u64, max_age_ms: u64) -> usize {
        let cutoff = now_ms.saturating_sub(max_age_ms);
        let to_drop: Vec<u64> = self.entries.iter()
            .filter(|(_, e)| e.last_seen_at_ms < cutoff)
            .map(|(k, _)| *k)
            .collect();
        let n = to_drop.len();
        for k in to_drop { self.entries.remove(&k); }
        n
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CacheError> {
        if self.schema_version != SCHEMA_VERSION { return Err(CacheError::SchemaMismatch); }
        Ok(())
    }
}

impl Default for ContentHashCache {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_observation_new() {
        let mut c = ContentHashCache::new();
        match c.observe(b"hello", 0) {
            ObserveVerdict::New { .. } => {}
            _ => panic!(),
        }
    }

    #[test]
    fn second_observation_existing() {
        let mut c = ContentHashCache::new();
        c.observe(b"hello", 0);
        match c.observe(b"hello", 100) {
            ObserveVerdict::Existing { seen_count, .. } => assert_eq!(seen_count, 2),
            _ => panic!(),
        }
    }

    #[test]
    fn different_content_separate_entries() {
        let mut c = ContentHashCache::new();
        c.observe(b"a", 0);
        c.observe(b"b", 0);
        assert_eq!(c.entries.len(), 2);
    }

    #[test]
    fn prune_drops_stale() {
        let mut c = ContentHashCache::new();
        c.observe(b"a", 0);
        c.observe(b"b", 5000);
        // Now 10_000, max_age 1000 → cutoff 9000. "a" stale (last=0), "b" recent (last=5000<9000 → also stale).
        let n = c.prune(10_000, 1000);
        assert_eq!(n, 2);
    }

    #[test]
    fn prune_keeps_recent() {
        let mut c = ContentHashCache::new();
        c.observe(b"a", 9500);
        let n = c.prune(10_000, 1000);
        assert_eq!(n, 0);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = ContentHashCache::new();
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), CacheError::SchemaMismatch));
    }

    #[test]
    fn cache_serde_roundtrip() {
        let mut c = ContentHashCache::new();
        c.observe(b"hello", 0);
        let j = serde_json::to_string(&c).unwrap();
        let back: ContentHashCache = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
