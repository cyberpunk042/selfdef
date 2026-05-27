//! `selfdef-vector-clock` — per-node sequence counters.
//!
//! tick(node) increments that node's counter. merge(other)
//! takes per-node max. compare(other) returns Ordering::Less
//! when self ⊑ other (≤ everywhere, < somewhere); Greater when
//! reverse; Equal when identical; None when concurrent.
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
pub struct VectorClock {
    /// Schema version.
    pub schema_version: String,
    /// node id → counter.
    pub counters: BTreeMap<String, u64>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum VcError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("node empty")]
    EmptyNode,
}

impl VectorClock {
    /// New empty.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            counters: BTreeMap::new(),
        }
    }

    /// Increment a node's counter.
    pub fn tick(&mut self, node: &str) -> Result<u64, VcError> {
        if node.is_empty() {
            return Err(VcError::EmptyNode);
        }
        let c = self.counters.entry(node.into()).or_insert(0);
        *c = c.saturating_add(1);
        Ok(*c)
    }

    /// Get counter for node (0 if absent).
    pub fn get(&self, node: &str) -> u64 {
        *self.counters.get(node).unwrap_or(&0)
    }

    /// Merge other's counters in (per-node max).
    pub fn merge(&mut self, other: &VectorClock) {
        for (k, &v) in &other.counters {
            let entry = self.counters.entry(k.clone()).or_insert(0);
            if v > *entry {
                *entry = v;
            }
        }
    }

    /// Compare two clocks.
    ///
    /// Returns:
    /// - `Some(Less)` if self ⊑ other (every node ≤, at least one <)
    /// - `Some(Greater)` if reverse
    /// - `Some(Equal)` if identical for all nodes
    /// - `None` if concurrent
    pub fn compare(&self, other: &VectorClock) -> Option<std::cmp::Ordering> {
        let mut nodes: std::collections::BTreeSet<&String> = std::collections::BTreeSet::new();
        nodes.extend(self.counters.keys());
        nodes.extend(other.counters.keys());
        let mut less = false;
        let mut greater = false;
        for n in nodes {
            let a = self.get(n);
            let b = other.get(n);
            if a < b {
                less = true;
            } else if a > b {
                greater = true;
            }
        }
        match (less, greater) {
            (false, false) => Some(std::cmp::Ordering::Equal),
            (true, false) => Some(std::cmp::Ordering::Less),
            (false, true) => Some(std::cmp::Ordering::Greater),
            (true, true) => None,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), VcError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(VcError::SchemaMismatch);
        }
        for k in self.counters.keys() {
            if k.is_empty() {
                return Err(VcError::EmptyNode);
            }
        }
        Ok(())
    }
}

impl Default for VectorClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn tick_increments() {
        let mut a = VectorClock::new();
        assert_eq!(a.tick("n1").unwrap(), 1);
        assert_eq!(a.tick("n1").unwrap(), 2);
        assert_eq!(a.tick("n2").unwrap(), 1);
        assert_eq!(a.get("n1"), 2);
        assert_eq!(a.get("n2"), 1);
        assert_eq!(a.get("missing"), 0);
    }

    #[test]
    fn merge_takes_max() {
        let mut a = VectorClock::new();
        a.tick("n1").unwrap();
        a.tick("n2").unwrap();
        a.tick("n2").unwrap();
        let mut b = VectorClock::new();
        b.tick("n1").unwrap();
        b.tick("n1").unwrap();
        a.merge(&b);
        assert_eq!(a.get("n1"), 2);
        assert_eq!(a.get("n2"), 2);
    }

    #[test]
    fn equal_clocks() {
        let mut a = VectorClock::new();
        a.tick("n1").unwrap();
        let mut b = VectorClock::new();
        b.tick("n1").unwrap();
        assert_eq!(a.compare(&b), Some(Ordering::Equal));
    }

    #[test]
    fn happens_before() {
        let mut a = VectorClock::new();
        a.tick("n1").unwrap();
        let mut b = a.clone();
        b.tick("n2").unwrap();
        assert_eq!(a.compare(&b), Some(Ordering::Less));
        assert_eq!(b.compare(&a), Some(Ordering::Greater));
    }

    #[test]
    fn concurrent() {
        let mut a = VectorClock::new();
        a.tick("n1").unwrap();
        let mut b = VectorClock::new();
        b.tick("n2").unwrap();
        assert_eq!(a.compare(&b), None);
    }

    #[test]
    fn empty_node_rejected() {
        let mut a = VectorClock::new();
        assert!(matches!(a.tick("").unwrap_err(), VcError::EmptyNode));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut a = VectorClock::new();
        a.schema_version = "9.9.9".into();
        assert!(matches!(a.validate().unwrap_err(), VcError::SchemaMismatch));
    }

    #[test]
    fn vc_serde_roundtrip() {
        let mut a = VectorClock::new();
        a.tick("n1").unwrap();
        let j = serde_json::to_string(&a).unwrap();
        let back: VectorClock = serde_json::from_str(&j).unwrap();
        assert_eq!(a, back);
    }
}
