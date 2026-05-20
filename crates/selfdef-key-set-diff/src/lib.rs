//! `selfdef-key-set-diff` — pairwise set diff.
//!
//! Diff{added, removed, common}. compute(prev, next) yields the
//! three disjoint subsets of (prev ∪ next). is_change_free
//! returns true iff added.is_empty() && removed.is_empty().
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Diff.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Diff {
    /// In next, not in prev.
    pub added: BTreeSet<String>,
    /// In prev, not in next.
    pub removed: BTreeSet<String>,
    /// In both.
    pub common: BTreeSet<String>,
}

/// Versioned state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeySetDiff {
    /// Schema version.
    pub schema_version: String,
    /// Latest diff (None until compute called).
    pub last: Option<Diff>,
    /// Number of diffs computed.
    pub computes: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DiffError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

impl Diff {
    /// Sizes.
    pub fn added_len(&self) -> usize { self.added.len() }
    /// Sizes.
    pub fn removed_len(&self) -> usize { self.removed.len() }
    /// Sizes.
    pub fn common_len(&self) -> usize { self.common.len() }
    /// True iff added/removed both empty.
    pub fn is_change_free(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

/// Compute diff (added/removed/common) between prev and next.
pub fn compute(prev: &BTreeSet<String>, next: &BTreeSet<String>) -> Diff {
    let added: BTreeSet<String> = next.difference(prev).cloned().collect();
    let removed: BTreeSet<String> = prev.difference(next).cloned().collect();
    let common: BTreeSet<String> = prev.intersection(next).cloned().collect();
    Diff { added, removed, common }
}

impl KeySetDiff {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            last: None,
            computes: 0,
        }
    }

    /// Compute + store as `last`.
    pub fn compute_and_store(&mut self, prev: &BTreeSet<String>, next: &BTreeSet<String>) -> &Diff {
        self.last = Some(compute(prev, next));
        self.computes = self.computes.saturating_add(1);
        self.last.as_ref().unwrap()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DiffError> {
        if self.schema_version != SCHEMA_VERSION { return Err(DiffError::SchemaMismatch); }
        Ok(())
    }
}

impl Default for KeySetDiff {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn empty_inputs() {
        let d = compute(&set(&[]), &set(&[]));
        assert!(d.is_change_free());
        assert_eq!(d.common_len(), 0);
    }

    #[test]
    fn added_only() {
        let d = compute(&set(&[]), &set(&["a", "b"]));
        assert_eq!(d.added_len(), 2);
        assert_eq!(d.removed_len(), 0);
        assert_eq!(d.common_len(), 0);
    }

    #[test]
    fn removed_only() {
        let d = compute(&set(&["a"]), &set(&[]));
        assert_eq!(d.removed_len(), 1);
    }

    #[test]
    fn typical_diff() {
        let prev = set(&["a", "b", "c"]);
        let next = set(&["b", "c", "d", "e"]);
        let d = compute(&prev, &next);
        assert_eq!(d.added, set(&["d", "e"]));
        assert_eq!(d.removed, set(&["a"]));
        assert_eq!(d.common, set(&["b", "c"]));
    }

    #[test]
    fn unchanged_is_change_free() {
        let s = set(&["x", "y"]);
        let d = compute(&s, &s);
        assert!(d.is_change_free());
        assert_eq!(d.common_len(), 2);
    }

    #[test]
    fn state_stores_last() {
        let mut k = KeySetDiff::new();
        k.compute_and_store(&set(&["a"]), &set(&["b"]));
        assert_eq!(k.computes, 1);
        assert_eq!(k.last.as_ref().unwrap().added, set(&["b"]));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut k = KeySetDiff::new();
        k.schema_version = "9.9.9".into();
        assert!(matches!(k.validate().unwrap_err(), DiffError::SchemaMismatch));
    }

    #[test]
    fn state_serde_roundtrip() {
        let mut k = KeySetDiff::new();
        k.compute_and_store(&set(&["a"]), &set(&["a", "b"]));
        let j = serde_json::to_string(&k).unwrap();
        let back: KeySetDiff = serde_json::from_str(&j).unwrap();
        assert_eq!(k, back);
    }
}
