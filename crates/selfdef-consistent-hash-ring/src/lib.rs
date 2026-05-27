//! `selfdef-consistent-hash-ring` — deterministic key→node assignment.
//!
//! Nodes register with vnode count. assign(key) hashes key to a
//! ring point and returns the first node clockwise. FNV-1a-64 for
//! both key + vnode hashing. Removing a node only reassigns keys
//! whose owner was that node.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Node record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Node {
    /// Node id.
    pub id: String,
    /// Virtual node count.
    pub vnodes: u32,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsistentHashRing {
    /// Schema version.
    pub schema_version: String,
    /// id → node.
    pub nodes: BTreeMap<String, Node>,
    /// ring point (u64) → node id; rebuilt on register/unregister.
    pub ring: BTreeMap<u64, String>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RingError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("node id empty")]
    EmptyId,
    /// Zero vnodes.
    #[error("vnodes must be >= 1")]
    ZeroVnodes,
    /// Duplicate.
    #[error("duplicate node: {0}")]
    DuplicateNode(String),
    /// Unknown.
    #[error("unknown node: {0}")]
    UnknownNode(String),
    /// Empty ring.
    #[error("ring is empty")]
    EmptyRing,
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn vnode_hash(node_id: &str, idx: u32) -> u64 {
    // Decimal-encode the index so successive vnodes diverge under FNV-1a-64.
    let mut buf = Vec::with_capacity(node_id.len() + 12);
    buf.extend_from_slice(node_id.as_bytes());
    buf.push(b'#');
    buf.extend_from_slice(idx.to_string().as_bytes());
    fnv1a_64(&buf)
}

impl ConsistentHashRing {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            nodes: BTreeMap::new(),
            ring: BTreeMap::new(),
        }
    }

    /// Register node with given vnode count.
    pub fn register(&mut self, id: &str, vnodes: u32) -> Result<(), RingError> {
        if id.is_empty() {
            return Err(RingError::EmptyId);
        }
        if vnodes == 0 {
            return Err(RingError::ZeroVnodes);
        }
        if self.nodes.contains_key(id) {
            return Err(RingError::DuplicateNode(id.into()));
        }
        self.nodes.insert(
            id.into(),
            Node {
                id: id.into(),
                vnodes,
            },
        );
        for i in 0..vnodes {
            self.ring.insert(vnode_hash(id, i), id.into());
        }
        Ok(())
    }

    /// Unregister node.
    pub fn unregister(&mut self, id: &str) -> Result<(), RingError> {
        let n = self
            .nodes
            .remove(id)
            .ok_or_else(|| RingError::UnknownNode(id.into()))?;
        for i in 0..n.vnodes {
            self.ring.remove(&vnode_hash(id, i));
        }
        Ok(())
    }

    /// Assign key to the first node clockwise from its hash.
    pub fn assign(&self, key: &str) -> Result<&str, RingError> {
        if self.ring.is_empty() {
            return Err(RingError::EmptyRing);
        }
        let h = fnv1a_64(key.as_bytes());
        let owner = self
            .ring
            .range(h..)
            .next()
            .or_else(|| self.ring.iter().next())
            .map(|(_, v)| v.as_str())
            .unwrap();
        Ok(owner)
    }

    /// Assign key to top-N replicas clockwise (deduped node ids).
    pub fn assign_replicas(&self, key: &str, n: usize) -> Result<Vec<String>, RingError> {
        if self.ring.is_empty() {
            return Err(RingError::EmptyRing);
        }
        let h = fnv1a_64(key.as_bytes());
        let mut out: Vec<String> = Vec::with_capacity(n);
        let iter = self.ring.range(h..).chain(self.ring.range(..h));
        for (_, node) in iter {
            if !out.iter().any(|s| s == node) {
                out.push(node.clone());
                if out.len() >= n {
                    break;
                }
            }
        }
        Ok(out)
    }

    /// Node count.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Ring slot count.
    pub fn slot_count(&self) -> usize {
        self.ring.len()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RingError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RingError::SchemaMismatch);
        }
        for (id, n) in &self.nodes {
            if id.is_empty() {
                return Err(RingError::EmptyId);
            }
            if n.vnodes == 0 {
                return Err(RingError::ZeroVnodes);
            }
        }
        Ok(())
    }
}

impl Default for ConsistentHashRing {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_ring_errors() {
        let r = ConsistentHashRing::new();
        assert!(matches!(r.assign("k").unwrap_err(), RingError::EmptyRing));
    }

    #[test]
    fn single_node_owns_all() {
        let mut r = ConsistentHashRing::new();
        r.register("n1", 16).unwrap();
        for k in &["a", "b", "c", "d", "e"] {
            assert_eq!(r.assign(k).unwrap(), "n1");
        }
    }

    #[test]
    fn distributes_across_nodes() {
        let mut r = ConsistentHashRing::new();
        r.register("n1", 64).unwrap();
        r.register("n2", 64).unwrap();
        r.register("n3", 64).unwrap();
        let mut seen = std::collections::BTreeSet::new();
        for k in 0..1000 {
            seen.insert(r.assign(&format!("key-{k}")).unwrap().to_string());
        }
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn deterministic_assignment() {
        let mut r = ConsistentHashRing::new();
        r.register("n1", 32).unwrap();
        r.register("n2", 32).unwrap();
        let a = r.assign("stable-key").unwrap().to_string();
        let b = r.assign("stable-key").unwrap().to_string();
        assert_eq!(a, b);
    }

    #[test]
    fn removal_reassigns_only_owner_keys() {
        let mut r = ConsistentHashRing::new();
        r.register("n1", 64).unwrap();
        r.register("n2", 64).unwrap();
        r.register("n3", 64).unwrap();
        let before: Vec<String> = (0..200)
            .map(|i| r.assign(&format!("key-{i}")).unwrap().to_string())
            .collect();
        r.unregister("n2").unwrap();
        let after: Vec<String> = (0..200)
            .map(|i| r.assign(&format!("key-{i}")).unwrap().to_string())
            .collect();
        for (b, a) in before.iter().zip(after.iter()) {
            if b == "n2" {
                assert_ne!(a, "n2");
            } else {
                assert_eq!(b, a);
            }
        }
    }

    #[test]
    fn replicas_are_distinct() {
        let mut r = ConsistentHashRing::new();
        r.register("n1", 16).unwrap();
        r.register("n2", 16).unwrap();
        r.register("n3", 16).unwrap();
        let reps = r.assign_replicas("key", 3).unwrap();
        assert_eq!(reps.len(), 3);
        let s: std::collections::BTreeSet<_> = reps.iter().collect();
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn duplicate_node_rejected() {
        let mut r = ConsistentHashRing::new();
        r.register("n1", 1).unwrap();
        assert!(matches!(
            r.register("n1", 1).unwrap_err(),
            RingError::DuplicateNode(_)
        ));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut r = ConsistentHashRing::new();
        assert!(matches!(r.register("", 1).unwrap_err(), RingError::EmptyId));
        assert!(matches!(
            r.register("n", 0).unwrap_err(),
            RingError::ZeroVnodes
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = ConsistentHashRing::new();
        r.schema_version = "9.9.9".into();
        assert!(matches!(
            r.validate().unwrap_err(),
            RingError::SchemaMismatch
        ));
    }

    #[test]
    fn ring_serde_roundtrip() {
        let mut r = ConsistentHashRing::new();
        r.register("n1", 4).unwrap();
        r.register("n2", 4).unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: ConsistentHashRing = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
