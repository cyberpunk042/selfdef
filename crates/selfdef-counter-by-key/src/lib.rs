//! `selfdef-counter-by-key` — per-key counters with rankings.
//!
//! Per arbitrary string key: cumulative count. inc/inc_by add;
//! top_k returns top by count desc with alpha tie-break;
//! grand_total sums.
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
pub struct CounterByKey {
    /// Schema version.
    pub schema_version: String,
    /// key → count.
    pub counts: BTreeMap<String, u64>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CounterError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("key empty")]
    EmptyKey,
}

impl CounterByKey {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            counts: BTreeMap::new(),
        }
    }

    /// Increment by 1.
    pub fn inc(&mut self, key: &str) -> Result<u64, CounterError> {
        if key.is_empty() { return Err(CounterError::EmptyKey); }
        let entry = self.counts.entry(key.into()).or_insert(0);
        *entry = entry.saturating_add(1);
        Ok(*entry)
    }

    /// Increment by n.
    pub fn inc_by(&mut self, key: &str, n: u64) -> Result<u64, CounterError> {
        if key.is_empty() { return Err(CounterError::EmptyKey); }
        let entry = self.counts.entry(key.into()).or_insert(0);
        *entry = entry.saturating_add(n);
        Ok(*entry)
    }

    /// Get count.
    pub fn get(&self, key: &str) -> u64 {
        self.counts.get(key).copied().unwrap_or(0)
    }

    /// Top-K.
    pub fn top_k(&self, k: usize) -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> = self.counts.iter().map(|(k, c)| (k.clone(), *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.truncate(k);
        v
    }

    /// Grand total.
    pub fn grand_total(&self) -> u64 {
        self.counts.values().fold(0u64, |a, b| a.saturating_add(*b))
    }

    /// Clear.
    pub fn clear(&mut self) {
        self.counts.clear();
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CounterError> {
        if self.schema_version != SCHEMA_VERSION { return Err(CounterError::SchemaMismatch); }
        for k in self.counts.keys() {
            if k.is_empty() { return Err(CounterError::EmptyKey); }
        }
        Ok(())
    }
}

impl Default for CounterByKey {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inc_returns_new_value() {
        let mut c = CounterByKey::new();
        assert_eq!(c.inc("a").unwrap(), 1);
        assert_eq!(c.inc("a").unwrap(), 2);
    }

    #[test]
    fn inc_by_n() {
        let mut c = CounterByKey::new();
        c.inc_by("a", 5).unwrap();
        c.inc_by("a", 3).unwrap();
        assert_eq!(c.get("a"), 8);
    }

    #[test]
    fn top_k_ordered() {
        let mut c = CounterByKey::new();
        c.inc_by("rare", 1).unwrap();
        c.inc_by("common", 100).unwrap();
        c.inc_by("medium", 50).unwrap();
        let t = c.top_k(2);
        assert_eq!(t[0].0, "common");
        assert_eq!(t[1].0, "medium");
    }

    #[test]
    fn tied_alpha_break() {
        let mut c = CounterByKey::new();
        c.inc_by("b", 5).unwrap();
        c.inc_by("a", 5).unwrap();
        let t = c.top_k(2);
        assert_eq!(t[0].0, "a");
    }

    #[test]
    fn grand_total() {
        let mut c = CounterByKey::new();
        c.inc_by("a", 10).unwrap();
        c.inc_by("b", 20).unwrap();
        assert_eq!(c.grand_total(), 30);
    }

    #[test]
    fn clear_resets() {
        let mut c = CounterByKey::new();
        c.inc("a").unwrap();
        c.clear();
        assert_eq!(c.grand_total(), 0);
    }

    #[test]
    fn empty_key_rejected() {
        let mut c = CounterByKey::new();
        assert!(matches!(c.inc("").unwrap_err(), CounterError::EmptyKey));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = CounterByKey::new();
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), CounterError::SchemaMismatch));
    }

    #[test]
    fn counter_serde_roundtrip() {
        let mut c = CounterByKey::new();
        c.inc("a").unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: CounterByKey = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
