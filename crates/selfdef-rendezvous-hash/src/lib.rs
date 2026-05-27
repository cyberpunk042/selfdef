//! `selfdef-rendezvous-hash` — Highest Random Weight (HRW).
//!
//! For each (key, node) compute h = FNV-1a-64(key + ":" + node);
//! the node with the highest h wins for that key. top_k(key, k)
//! returns the k highest-weighted nodes in descending order
//! (replica set). Adding a node moves only ~1/N of keys; removing
//! a node redistributes its keys to the next-highest of EACH key
//! (no hot spot).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RendezvousHash {
    /// Schema version.
    pub schema_version: String,
    /// Node id set.
    pub nodes: BTreeSet<String>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum HrwError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("node id empty")]
    EmptyNode,
    /// No nodes.
    #[error("no nodes registered")]
    NoNodes,
    /// Bad k.
    #[error("k must be in 1..=nodes.len()")]
    BadK,
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn weight(key: &str, node: &str) -> u64 {
    let mut buf = key.as_bytes().to_vec();
    buf.push(b':');
    buf.extend_from_slice(node.as_bytes());
    fnv1a_64(&buf)
}

impl RendezvousHash {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            nodes: BTreeSet::new(),
        }
    }

    /// Add a node.
    pub fn add_node(&mut self, node: &str) -> Result<(), HrwError> {
        if node.is_empty() {
            return Err(HrwError::EmptyNode);
        }
        self.nodes.insert(node.into());
        Ok(())
    }

    /// Remove a node.
    pub fn remove_node(&mut self, node: &str) {
        self.nodes.remove(node);
    }

    /// Highest-weight node for key.
    pub fn assign(&self, key: &str) -> Result<&str, HrwError> {
        if self.nodes.is_empty() {
            return Err(HrwError::NoNodes);
        }
        let best = self.nodes.iter().max_by_key(|n| weight(key, n)).unwrap();
        Ok(best)
    }

    /// Top-k nodes for key in descending-weight order.
    pub fn top_k(&self, key: &str, k: usize) -> Result<Vec<&str>, HrwError> {
        if self.nodes.is_empty() {
            return Err(HrwError::NoNodes);
        }
        if k == 0 || k > self.nodes.len() {
            return Err(HrwError::BadK);
        }
        let mut by_weight: Vec<(u64, &str)> = self
            .nodes
            .iter()
            .map(|n| (weight(key, n), n.as_str()))
            .collect();
        by_weight.sort_by(|a, b| b.0.cmp(&a.0));
        Ok(by_weight.into_iter().take(k).map(|(_, n)| n).collect())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), HrwError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(HrwError::SchemaMismatch);
        }
        for n in &self.nodes {
            if n.is_empty() {
                return Err(HrwError::EmptyNode);
            }
        }
        Ok(())
    }
}

impl Default for RendezvousHash {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn h() -> RendezvousHash {
        let mut h = RendezvousHash::new();
        for n in &["a", "b", "c", "d", "e"] {
            h.add_node(n).unwrap();
        }
        h
    }

    #[test]
    fn assign_returns_some_node() {
        let h = h();
        let n = h.assign("k").unwrap();
        assert!(["a", "b", "c", "d", "e"].contains(&n));
    }

    #[test]
    fn deterministic_same_key() {
        let h = h();
        assert_eq!(h.assign("k").unwrap(), h.assign("k").unwrap());
    }

    #[test]
    fn top_k_returns_k_distinct() {
        let h = h();
        let top = h.top_k("k", 3).unwrap();
        assert_eq!(top.len(), 3);
        let mut set: BTreeSet<&str> = BTreeSet::new();
        for n in &top {
            set.insert(n);
        }
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn no_nodes_rejected() {
        let h = RendezvousHash::new();
        assert!(matches!(h.assign("k").unwrap_err(), HrwError::NoNodes));
    }

    #[test]
    fn bad_k_rejected() {
        let h = h();
        assert!(matches!(h.top_k("k", 0).unwrap_err(), HrwError::BadK));
        assert!(matches!(h.top_k("k", 6).unwrap_err(), HrwError::BadK));
    }

    #[test]
    fn removing_node_redistributes() {
        // Pick a key whose primary is "c"; after removing "c" the
        // new assignment should not be "c" but must remain stable
        // across calls.
        let mut h = h();
        let mut victims: Vec<&str> = Vec::new();
        for i in 0..1000 {
            let k = format!("k{}", i);
            if h.assign(&k).unwrap() == "c" {
                victims.push(Box::leak(k.into_boxed_str()));
            }
            if victims.len() > 10 {
                break;
            }
        }
        h.remove_node("c");
        for v in &victims {
            let after = h.assign(v).unwrap();
            assert!(after != "c");
        }
    }

    #[test]
    fn empty_node_rejected() {
        let mut h = RendezvousHash::new();
        assert!(matches!(h.add_node("").unwrap_err(), HrwError::EmptyNode));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut h = RendezvousHash::new();
        h.schema_version = "9.9.9".into();
        assert!(matches!(
            h.validate().unwrap_err(),
            HrwError::SchemaMismatch
        ));
    }

    #[test]
    fn hash_serde_roundtrip() {
        let h = h();
        let j = serde_json::to_string(&h).unwrap();
        let back: RendezvousHash = serde_json::from_str(&j).unwrap();
        assert_eq!(h, back);
    }
}
