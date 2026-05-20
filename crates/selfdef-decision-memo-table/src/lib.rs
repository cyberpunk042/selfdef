//! `selfdef-decision-memo-table` — cached policy decisions.
//!
//! Keyed by (input_hash, policy_version). store records; lookup
//! returns cached or None. invalidate_version drops all entries
//! for a given policy_version.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Cached entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheEntry {
    /// Decision label.
    pub decision: String,
    /// Recorded ts.
    pub ts_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionMemoTable {
    /// Schema version.
    pub schema_version: String,
    /// Inner: policy_version → (input_hash → entry).
    pub by_version: BTreeMap<String, BTreeMap<u64, CacheEntry>>,
    /// Hits.
    pub hits: u64,
    /// Misses.
    pub misses: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum MemoError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("policy_version empty")]
    EmptyVersion,
    /// Empty.
    #[error("decision empty")]
    EmptyDecision,
}

impl DecisionMemoTable {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            by_version: BTreeMap::new(),
            hits: 0,
            misses: 0,
        }
    }

    /// Store.
    pub fn store(&mut self, policy_version: &str, input_hash: u64, decision: &str, ts_ms: u64) -> Result<(), MemoError> {
        if policy_version.is_empty() { return Err(MemoError::EmptyVersion); }
        if decision.is_empty() { return Err(MemoError::EmptyDecision); }
        self.by_version.entry(policy_version.into()).or_default().insert(input_hash, CacheEntry {
            decision: decision.into(),
            ts_ms,
        });
        Ok(())
    }

    /// Lookup (mut → bumps hit/miss counters).
    pub fn lookup(&mut self, policy_version: &str, input_hash: u64) -> Option<String> {
        let hit = self.by_version.get(policy_version).and_then(|m| m.get(&input_hash)).map(|e| e.decision.clone());
        if hit.is_some() {
            self.hits = self.hits.saturating_add(1);
        } else {
            self.misses = self.misses.saturating_add(1);
        }
        hit
    }

    /// Invalidate all entries for a policy version.
    pub fn invalidate_version(&mut self, policy_version: &str) -> usize {
        self.by_version.remove(policy_version).map(|m| m.len()).unwrap_or(0)
    }

    /// Total cached.
    pub fn len(&self) -> usize {
        self.by_version.values().map(|m| m.len()).sum()
    }

    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), MemoError> {
        if self.schema_version != SCHEMA_VERSION { return Err(MemoError::SchemaMismatch); }
        for (v, m) in &self.by_version {
            if v.is_empty() { return Err(MemoError::EmptyVersion); }
            for e in m.values() {
                if e.decision.is_empty() { return Err(MemoError::EmptyDecision); }
            }
        }
        Ok(())
    }
}

impl Default for DecisionMemoTable {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_then_lookup_hit() {
        let mut t = DecisionMemoTable::new();
        t.store("v1", 0xabc, "allow", 0).unwrap();
        assert_eq!(t.lookup("v1", 0xabc).as_deref(), Some("allow"));
        assert_eq!(t.hits, 1);
    }

    #[test]
    fn lookup_miss_increments() {
        let mut t = DecisionMemoTable::new();
        assert!(t.lookup("v1", 0xabc).is_none());
        assert_eq!(t.misses, 1);
    }

    #[test]
    fn version_isolated() {
        let mut t = DecisionMemoTable::new();
        t.store("v1", 0xabc, "allow", 0).unwrap();
        assert!(t.lookup("v2", 0xabc).is_none());
    }

    #[test]
    fn invalidate_drops() {
        let mut t = DecisionMemoTable::new();
        t.store("v1", 0xabc, "allow", 0).unwrap();
        t.store("v1", 0xdef, "deny", 0).unwrap();
        assert_eq!(t.invalidate_version("v1"), 2);
        assert!(t.lookup("v1", 0xabc).is_none());
    }

    #[test]
    fn len_sums_across_versions() {
        let mut t = DecisionMemoTable::new();
        t.store("v1", 1, "a", 0).unwrap();
        t.store("v2", 2, "b", 0).unwrap();
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut t = DecisionMemoTable::new();
        assert!(matches!(t.store("", 1, "a", 0).unwrap_err(), MemoError::EmptyVersion));
        assert!(matches!(t.store("v", 1, "", 0).unwrap_err(), MemoError::EmptyDecision));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = DecisionMemoTable::new();
        t.schema_version = "9.9.9".into();
        assert!(matches!(t.validate().unwrap_err(), MemoError::SchemaMismatch));
    }

    #[test]
    fn memo_serde_roundtrip() {
        let mut t = DecisionMemoTable::new();
        t.store("v1", 0xabc, "allow", 0).unwrap();
        let j = serde_json::to_string(&t).unwrap();
        let back: DecisionMemoTable = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
