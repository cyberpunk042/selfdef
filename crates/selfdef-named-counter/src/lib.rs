//! `selfdef-named-counter` — multi-named-counter store.
//!
//! inc(name, by) saturating-adds. dec(name, by) saturating-subs.
//! get(name) reads (0 if absent). snapshot() returns sorted
//! BTreeMap copy. reset_all zeroes all counters (keeps keys).
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
pub struct NamedCounter {
    /// Schema version.
    pub schema_version: String,
    /// name → counter.
    pub counters: BTreeMap<String, u64>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CounterError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("name empty")]
    EmptyName,
}

impl NamedCounter {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            counters: BTreeMap::new(),
        }
    }

    /// Increment (saturating).
    pub fn inc(&mut self, name: &str, by: u64) -> Result<u64, CounterError> {
        if name.is_empty() {
            return Err(CounterError::EmptyName);
        }
        let c = self.counters.entry(name.into()).or_insert(0);
        *c = c.saturating_add(by);
        Ok(*c)
    }

    /// Decrement (saturating at 0).
    pub fn dec(&mut self, name: &str, by: u64) -> Result<u64, CounterError> {
        if name.is_empty() {
            return Err(CounterError::EmptyName);
        }
        let c = self.counters.entry(name.into()).or_insert(0);
        *c = c.saturating_sub(by);
        Ok(*c)
    }

    /// Get (0 if absent).
    pub fn get(&self, name: &str) -> u64 {
        *self.counters.get(name).unwrap_or(&0)
    }

    /// Reset all counters to 0 (keys preserved).
    pub fn reset_all(&mut self) {
        for v in self.counters.values_mut() {
            *v = 0;
        }
    }

    /// Snapshot.
    pub fn snapshot(&self) -> BTreeMap<String, u64> {
        self.counters.clone()
    }

    /// Total of all counters.
    pub fn total(&self) -> u128 {
        self.counters.values().map(|v| *v as u128).sum()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CounterError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CounterError::SchemaMismatch);
        }
        for k in self.counters.keys() {
            if k.is_empty() {
                return Err(CounterError::EmptyName);
            }
        }
        Ok(())
    }
}

impl Default for NamedCounter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inc_creates_and_adds() {
        let mut c = NamedCounter::new();
        assert_eq!(c.inc("a", 1).unwrap(), 1);
        assert_eq!(c.inc("a", 4).unwrap(), 5);
        assert_eq!(c.get("a"), 5);
    }

    #[test]
    fn dec_saturates_at_zero() {
        let mut c = NamedCounter::new();
        c.inc("a", 5).unwrap();
        assert_eq!(c.dec("a", 100).unwrap(), 0);
    }

    #[test]
    fn missing_returns_zero() {
        let c = NamedCounter::new();
        assert_eq!(c.get("nope"), 0);
    }

    #[test]
    fn reset_all_zeroes() {
        let mut c = NamedCounter::new();
        c.inc("a", 5).unwrap();
        c.inc("b", 3).unwrap();
        c.reset_all();
        assert_eq!(c.get("a"), 0);
        assert_eq!(c.get("b"), 0);
    }

    #[test]
    fn total_sums() {
        let mut c = NamedCounter::new();
        c.inc("a", 5).unwrap();
        c.inc("b", 3).unwrap();
        assert_eq!(c.total(), 8);
    }

    #[test]
    fn snapshot_returns_copy() {
        let mut c = NamedCounter::new();
        c.inc("a", 5).unwrap();
        let snap = c.snapshot();
        assert_eq!(snap.get("a"), Some(&5));
        c.inc("a", 100).unwrap();
        assert_eq!(snap.get("a"), Some(&5)); // snapshot frozen
    }

    #[test]
    fn empty_name_rejected() {
        let mut c = NamedCounter::new();
        assert!(matches!(c.inc("", 1).unwrap_err(), CounterError::EmptyName));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = NamedCounter::new();
        c.schema_version = "9.9.9".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            CounterError::SchemaMismatch
        ));
    }

    #[test]
    fn counter_serde_roundtrip() {
        let mut c = NamedCounter::new();
        c.inc("a", 5).unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: NamedCounter = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
