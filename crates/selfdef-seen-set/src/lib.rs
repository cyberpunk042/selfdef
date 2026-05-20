//! `selfdef-seen-set` — bounded TTL seen-set.
//!
//! first_time(id, now_ms) returns true on the first observation
//! of id within TTL window (and records); subsequent obs return
//! false. Capacity-bounded: when full, evicts the oldest entry.
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
pub struct SeenSet {
    /// Schema version.
    pub schema_version: String,
    /// Capacity.
    pub capacity: u32,
    /// TTL ms.
    pub ttl_ms: u64,
    /// id → first-seen ts ms.
    pub seen: BTreeMap<String, u64>,
    /// Total observations.
    pub observations: u64,
    /// First-time count.
    pub first_times: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SeenError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("id empty")]
    EmptyId,
    /// Zero.
    #[error("capacity/ttl_ms must be >= 1")]
    ZeroParameter,
}

impl SeenSet {
    /// New.
    pub fn new(capacity: u32, ttl_ms: u64) -> Result<Self, SeenError> {
        if capacity == 0 || ttl_ms == 0 { return Err(SeenError::ZeroParameter); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            capacity,
            ttl_ms,
            seen: BTreeMap::new(),
            observations: 0,
            first_times: 0,
        })
    }

    /// First-time observation?
    pub fn first_time(&mut self, id: &str, now_ms: u64) -> Result<bool, SeenError> {
        if id.is_empty() { return Err(SeenError::EmptyId); }
        self.observations = self.observations.saturating_add(1);
        // Lazy TTL prune for this id.
        if let Some(&ts) = self.seen.get(id) {
            if now_ms.saturating_sub(ts) < self.ttl_ms {
                return Ok(false);
            }
            self.seen.remove(id);
        }
        // Capacity check.
        if (self.seen.len() as u32) >= self.capacity {
            // Evict oldest.
            let oldest = self.seen.iter().min_by_key(|(_, ts)| *ts).map(|(k, _)| k.clone());
            if let Some(k) = oldest { self.seen.remove(&k); }
        }
        self.seen.insert(id.into(), now_ms);
        self.first_times = self.first_times.saturating_add(1);
        Ok(true)
    }

    /// Sweep expired.
    pub fn sweep(&mut self, now_ms: u64) -> u32 {
        let stale: Vec<String> = self.seen.iter()
            .filter(|(_, ts)| now_ms.saturating_sub(**ts) >= self.ttl_ms)
            .map(|(k, _)| k.clone())
            .collect();
        let n = stale.len() as u32;
        for k in stale { self.seen.remove(&k); }
        n
    }

    /// Count.
    pub fn len(&self) -> usize { self.seen.len() }

    /// Empty?
    pub fn is_empty(&self) -> bool { self.seen.is_empty() }

    /// Validate.
    pub fn validate(&self) -> Result<(), SeenError> {
        if self.schema_version != SCHEMA_VERSION { return Err(SeenError::SchemaMismatch); }
        if self.capacity == 0 || self.ttl_ms == 0 { return Err(SeenError::ZeroParameter); }
        for k in self.seen.keys() {
            if k.is_empty() { return Err(SeenError::EmptyId); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_time_true_then_false() {
        let mut s = SeenSet::new(5, 1000).unwrap();
        assert!(s.first_time("a", 0).unwrap());
        assert!(!s.first_time("a", 100).unwrap());
        assert_eq!(s.observations, 2);
        assert_eq!(s.first_times, 1);
    }

    #[test]
    fn after_ttl_first_time_again() {
        let mut s = SeenSet::new(5, 1000).unwrap();
        s.first_time("a", 0).unwrap();
        assert!(s.first_time("a", 1500).unwrap());
    }

    #[test]
    fn capacity_evicts_oldest() {
        let mut s = SeenSet::new(2, 10_000).unwrap();
        s.first_time("a", 0).unwrap();
        s.first_time("b", 100).unwrap();
        s.first_time("c", 200).unwrap();
        // "a" oldest → evicted.
        assert!(!s.seen.contains_key("a"));
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn sweep_removes_expired() {
        let mut s = SeenSet::new(5, 1000).unwrap();
        s.first_time("a", 0).unwrap();
        s.first_time("b", 0).unwrap();
        assert_eq!(s.sweep(2000), 2);
        assert!(s.is_empty());
    }

    #[test]
    fn empty_id_rejected() {
        let mut s = SeenSet::new(5, 1000).unwrap();
        assert!(matches!(s.first_time("", 0).unwrap_err(), SeenError::EmptyId));
    }

    #[test]
    fn zero_param_rejected() {
        assert!(matches!(SeenSet::new(0, 1000).unwrap_err(), SeenError::ZeroParameter));
        assert!(matches!(SeenSet::new(5, 0).unwrap_err(), SeenError::ZeroParameter));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = SeenSet::new(5, 1000).unwrap();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), SeenError::SchemaMismatch));
    }

    #[test]
    fn set_serde_roundtrip() {
        let mut s = SeenSet::new(5, 1000).unwrap();
        s.first_time("a", 0).unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: SeenSet = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
