//! `selfdef-frequency-map` — bounded key→count.
//!
//! observe(key) increments. When at capacity and key is new,
//! evicts the lowest-count entry (ties: lexicographic key for
//! determinism). top_n(n) returns up to n (key, count) pairs
//! sorted by count desc + key asc.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrequencyMap {
    /// Schema version.
    pub schema_version: String,
    /// Capacity.
    pub capacity: u32,
    /// key → count.
    pub counts: BTreeMap<String, u64>,
    /// Evictions.
    pub evictions: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum FreqError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("key empty")]
    EmptyKey,
    /// Zero capacity.
    #[error("capacity must be >= 1")]
    ZeroCapacity,
}

impl FrequencyMap {
    /// New.
    pub fn new(capacity: u32) -> Result<Self, FreqError> {
        if capacity == 0 {
            return Err(FreqError::ZeroCapacity);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            capacity,
            counts: BTreeMap::new(),
            evictions: 0,
        })
    }

    /// Observe.
    pub fn observe(&mut self, key: &str) -> Result<(), FreqError> {
        if key.is_empty() {
            return Err(FreqError::EmptyKey);
        }
        if let Some(c) = self.counts.get_mut(key) {
            *c = c.saturating_add(1);
            return Ok(());
        }
        if (self.counts.len() as u32) >= self.capacity {
            // Evict lowest-count (ties: lexicographic).
            let (k_evict, _) = self
                .counts
                .iter()
                .min_by(|(ka, va), (kb, vb)| va.cmp(vb).then(ka.cmp(kb)))
                .map(|(k, v)| (k.clone(), *v))
                .unwrap();
            self.counts.remove(&k_evict);
            self.evictions = self.evictions.saturating_add(1);
        }
        self.counts.insert(key.into(), 1);
        Ok(())
    }

    /// Top n by count desc then key asc.
    pub fn top_n(&self, n: usize) -> Vec<(String, u64)> {
        let mut all: Vec<(String, u64)> =
            self.counts.iter().map(|(k, v)| (k.clone(), *v)).collect();
        all.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        all.into_iter().take(n).collect()
    }

    /// Count for key.
    pub fn count(&self, key: &str) -> u64 {
        *self.counts.get(key).unwrap_or(&0)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), FreqError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(FreqError::SchemaMismatch);
        }
        if self.capacity == 0 {
            return Err(FreqError::ZeroCapacity);
        }
        for k in self.counts.keys() {
            if k.is_empty() {
                return Err(FreqError::EmptyKey);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observe_counts() {
        let mut f = FrequencyMap::new(10).unwrap();
        f.observe("a").unwrap();
        f.observe("a").unwrap();
        f.observe("b").unwrap();
        assert_eq!(f.count("a"), 2);
        assert_eq!(f.count("b"), 1);
        assert_eq!(f.count("c"), 0);
    }

    #[test]
    fn top_n_orders() {
        let mut f = FrequencyMap::new(10).unwrap();
        for _ in 0..5 {
            f.observe("a").unwrap();
        }
        for _ in 0..3 {
            f.observe("b").unwrap();
        }
        for _ in 0..7 {
            f.observe("c").unwrap();
        }
        let top = f.top_n(2);
        assert_eq!(top, vec![("c".into(), 7), ("a".into(), 5)]);
    }

    #[test]
    fn eviction_low_count() {
        let mut f = FrequencyMap::new(2).unwrap();
        for _ in 0..5 {
            f.observe("a").unwrap();
        }
        for _ in 0..2 {
            f.observe("b").unwrap();
        }
        // "b" has lower count; new key "c" → evicts "b".
        f.observe("c").unwrap();
        assert_eq!(f.evictions, 1);
        assert_eq!(f.count("b"), 0);
        assert_eq!(f.count("a"), 5);
        assert_eq!(f.count("c"), 1);
    }

    #[test]
    fn known_key_re_observe_no_eviction() {
        let mut f = FrequencyMap::new(2).unwrap();
        f.observe("a").unwrap();
        f.observe("b").unwrap();
        f.observe("a").unwrap();
        assert_eq!(f.evictions, 0);
        assert_eq!(f.count("a"), 2);
    }

    #[test]
    fn top_n_ties_break_by_key() {
        let mut f = FrequencyMap::new(5).unwrap();
        f.observe("b").unwrap();
        f.observe("a").unwrap();
        let top = f.top_n(2);
        assert_eq!(top[0].0, "a"); // tie at 1 → 'a' < 'b'
    }

    #[test]
    fn bad_inputs_rejected() {
        let mut f = FrequencyMap::new(5).unwrap();
        assert!(matches!(f.observe("").unwrap_err(), FreqError::EmptyKey));
        assert!(matches!(
            FrequencyMap::new(0).unwrap_err(),
            FreqError::ZeroCapacity
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut f = FrequencyMap::new(5).unwrap();
        f.schema_version = "9.9.9".into();
        assert!(matches!(
            f.validate().unwrap_err(),
            FreqError::SchemaMismatch
        ));
    }

    #[test]
    fn map_serde_roundtrip() {
        let mut f = FrequencyMap::new(5).unwrap();
        f.observe("a").unwrap();
        let j = serde_json::to_string(&f).unwrap();
        let back: FrequencyMap = serde_json::from_str(&j).unwrap();
        assert_eq!(f, back);
    }
}
