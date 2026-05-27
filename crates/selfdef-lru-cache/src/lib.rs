//! `selfdef-lru-cache` — bounded LRU.
//!
//! Each entry has a monotonic `tick` recorded on access. `get(key)`
//! returns the value (touching recency); `put(key, value)` inserts
//! (evicting the lowest-tick entry if at capacity). `peek(key)`
//! returns without touching recency.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// Value.
    pub value: String,
    /// Last access tick.
    pub tick: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LruCache {
    /// Schema version.
    pub schema_version: String,
    /// Capacity.
    pub capacity: usize,
    /// Entries.
    pub entries: BTreeMap<String, Entry>,
    /// Next tick.
    pub next_tick: u64,
    /// Eviction counter.
    pub evictions: u64,
    /// Hit counter.
    pub hits: u64,
    /// Miss counter.
    pub misses: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum LruError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero capacity.
    #[error("capacity must be > 0")]
    ZeroCapacity,
    /// Empty key.
    #[error("key empty")]
    EmptyKey,
}

impl LruCache {
    /// New.
    pub fn new(capacity: usize) -> Result<Self, LruError> {
        if capacity == 0 {
            return Err(LruError::ZeroCapacity);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            capacity,
            entries: BTreeMap::new(),
            next_tick: 1,
            evictions: 0,
            hits: 0,
            misses: 0,
        })
    }

    /// Get + touch.
    pub fn get(&mut self, key: &str) -> Option<String> {
        let tick = self.next_tick;
        let result = if let Some(e) = self.entries.get_mut(key) {
            e.tick = tick;
            Some(e.value.clone())
        } else {
            None
        };
        if result.is_some() {
            self.next_tick = self.next_tick.wrapping_add(1);
            self.hits = self.hits.saturating_add(1);
        } else {
            self.misses = self.misses.saturating_add(1);
        }
        result
    }

    /// Peek (no touch).
    pub fn peek(&self, key: &str) -> Option<String> {
        self.entries.get(key).map(|e| e.value.clone())
    }

    /// Put.
    pub fn put(&mut self, key: &str, value: &str) -> Result<(), LruError> {
        if key.is_empty() {
            return Err(LruError::EmptyKey);
        }
        let tick = self.next_tick;
        self.next_tick = self.next_tick.wrapping_add(1);
        if self.entries.contains_key(key) {
            // Update + touch.
            self.entries.insert(
                key.into(),
                Entry {
                    value: value.into(),
                    tick,
                },
            );
            return Ok(());
        }
        if self.entries.len() == self.capacity {
            // Evict lowest tick.
            let victim_key = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.tick)
                .map(|(k, _)| k.clone());
            if let Some(k) = victim_key {
                self.entries.remove(&k);
                self.evictions = self.evictions.saturating_add(1);
            }
        }
        self.entries.insert(
            key.into(),
            Entry {
                value: value.into(),
                tick,
            },
        );
        Ok(())
    }

    /// Remove.
    pub fn remove(&mut self, key: &str) -> bool {
        self.entries.remove(key).is_some()
    }

    /// Length.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), LruError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(LruError::SchemaMismatch);
        }
        if self.capacity == 0 {
            return Err(LruError::ZeroCapacity);
        }
        for k in self.entries.keys() {
            if k.is_empty() {
                return Err(LruError::EmptyKey);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_and_get() {
        let mut c = LruCache::new(2).unwrap();
        c.put("a", "1").unwrap();
        assert_eq!(c.get("a"), Some("1".into()));
        assert_eq!(c.hits, 1);
    }

    #[test]
    fn miss_increments_misses() {
        let mut c = LruCache::new(2).unwrap();
        assert!(c.get("nope").is_none());
        assert_eq!(c.misses, 1);
    }

    #[test]
    fn eviction_drops_least_recent() {
        let mut c = LruCache::new(2).unwrap();
        c.put("a", "1").unwrap();
        c.put("b", "2").unwrap();
        c.get("a"); // touch a
        c.put("c", "3").unwrap(); // evicts b (oldest tick)
        assert!(c.peek("b").is_none());
        assert!(c.peek("a").is_some());
        assert!(c.peek("c").is_some());
        assert_eq!(c.evictions, 1);
    }

    #[test]
    fn update_does_not_evict() {
        let mut c = LruCache::new(2).unwrap();
        c.put("a", "1").unwrap();
        c.put("a", "2").unwrap();
        assert_eq!(c.peek("a"), Some("2".into()));
        assert_eq!(c.evictions, 0);
    }

    #[test]
    fn peek_does_not_touch() {
        let mut c = LruCache::new(2).unwrap();
        c.put("a", "1").unwrap();
        c.put("b", "2").unwrap();
        let tick_a_before = c.entries["a"].tick;
        c.peek("a");
        assert_eq!(c.entries["a"].tick, tick_a_before);
    }

    #[test]
    fn remove() {
        let mut c = LruCache::new(2).unwrap();
        c.put("a", "1").unwrap();
        assert!(c.remove("a"));
        assert!(!c.remove("a"));
        assert!(c.is_empty());
    }

    #[test]
    fn zero_capacity_rejected() {
        assert!(matches!(
            LruCache::new(0).unwrap_err(),
            LruError::ZeroCapacity
        ));
    }

    #[test]
    fn empty_key_rejected() {
        let mut c = LruCache::new(2).unwrap();
        assert!(matches!(c.put("", "x").unwrap_err(), LruError::EmptyKey));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = LruCache::new(2).unwrap();
        c.schema_version = "9.9.9".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            LruError::SchemaMismatch
        ));
    }

    #[test]
    fn lru_serde_roundtrip() {
        let mut c = LruCache::new(3).unwrap();
        c.put("a", "1").unwrap();
        c.put("b", "2").unwrap();
        c.get("a");
        let j = serde_json::to_string(&c).unwrap();
        let back: LruCache = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
