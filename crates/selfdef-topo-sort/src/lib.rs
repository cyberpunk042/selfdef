//! `selfdef-topo-sort` — string-keyed DAG topological sort.
//!
//! add_node + add_edge(from, to). sort() returns Vec<String> in
//! topo order (Kahn's algorithm) iff acyclic; CycleDetected
//! otherwise. Within ties (multiple zero-indegree nodes), order
//! is BTreeSet-sorted for determinism.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopoSort {
    /// Schema version.
    pub schema_version: String,
    /// node id → outgoing edges.
    pub nodes: BTreeMap<String, BTreeSet<String>>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum TopoError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("node id empty")]
    EmptyNode,
    /// Duplicate.
    #[error("duplicate node: {0}")]
    DuplicateNode(String),
    /// Unknown.
    #[error("unknown node: {0}")]
    UnknownNode(String),
    /// Self-edge.
    #[error("self-edge: {0}")]
    SelfEdge(String),
    /// Cycle.
    #[error("cycle detected")]
    CycleDetected,
}

impl TopoSort {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            nodes: BTreeMap::new(),
        }
    }

    /// Add node.
    pub fn add_node(&mut self, id: &str) -> Result<(), TopoError> {
        if id.is_empty() {
            return Err(TopoError::EmptyNode);
        }
        if self.nodes.contains_key(id) {
            return Err(TopoError::DuplicateNode(id.into()));
        }
        self.nodes.insert(id.into(), BTreeSet::new());
        Ok(())
    }

    /// Add edge from → to.
    pub fn add_edge(&mut self, from: &str, to: &str) -> Result<(), TopoError> {
        if from == to {
            return Err(TopoError::SelfEdge(from.into()));
        }
        if !self.nodes.contains_key(from) {
            return Err(TopoError::UnknownNode(from.into()));
        }
        if !self.nodes.contains_key(to) {
            return Err(TopoError::UnknownNode(to.into()));
        }
        self.nodes.get_mut(from).unwrap().insert(to.into());
        Ok(())
    }

    /// Kahn topological sort.
    pub fn sort(&self) -> Result<Vec<String>, TopoError> {
        // Indegree.
        let mut indegree: BTreeMap<String, u32> =
            self.nodes.keys().map(|k| (k.clone(), 0)).collect();
        for outs in self.nodes.values() {
            for v in outs {
                *indegree.get_mut(v).unwrap() += 1;
            }
        }
        let mut ready: BTreeSet<String> = indegree
            .iter()
            .filter(|&(_, &d)| d == 0)
            .map(|(k, _)| k.clone())
            .collect();
        let mut out: Vec<String> = Vec::with_capacity(self.nodes.len());
        while let Some(n) = ready.iter().next().cloned() {
            ready.remove(&n);
            out.push(n.clone());
            for v in self.nodes.get(&n).unwrap().iter() {
                let d = indegree.get_mut(v).unwrap();
                *d -= 1;
                if *d == 0 {
                    ready.insert(v.clone());
                }
            }
        }
        if out.len() != self.nodes.len() {
            return Err(TopoError::CycleDetected);
        }
        Ok(out)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), TopoError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(TopoError::SchemaMismatch);
        }
        for (k, outs) in &self.nodes {
            if k.is_empty() {
                return Err(TopoError::EmptyNode);
            }
            for v in outs {
                if !self.nodes.contains_key(v) {
                    return Err(TopoError::UnknownNode(v.clone()));
                }
            }
        }
        Ok(())
    }
}

impl Default for TopoSort {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_sorts_to_empty() {
        let t = TopoSort::new();
        assert_eq!(t.sort().unwrap(), Vec::<String>::new());
    }

    #[test]
    fn linear_chain() {
        let mut t = TopoSort::new();
        t.add_node("a").unwrap();
        t.add_node("b").unwrap();
        t.add_node("c").unwrap();
        t.add_edge("a", "b").unwrap();
        t.add_edge("b", "c").unwrap();
        assert_eq!(t.sort().unwrap(), vec!["a", "b", "c"]);
    }

    #[test]
    fn diamond() {
        let mut t = TopoSort::new();
        for n in &["a", "b", "c", "d"] {
            t.add_node(n).unwrap();
        }
        t.add_edge("a", "b").unwrap();
        t.add_edge("a", "c").unwrap();
        t.add_edge("b", "d").unwrap();
        t.add_edge("c", "d").unwrap();
        let s = t.sort().unwrap();
        let pos = |x: &str| s.iter().position(|y| y == x).unwrap();
        assert!(pos("a") < pos("b"));
        assert!(pos("a") < pos("c"));
        assert!(pos("b") < pos("d"));
        assert!(pos("c") < pos("d"));
    }

    #[test]
    fn cycle_detected() {
        let mut t = TopoSort::new();
        t.add_node("a").unwrap();
        t.add_node("b").unwrap();
        t.add_edge("a", "b").unwrap();
        t.add_edge("b", "a").unwrap();
        assert!(matches!(t.sort().unwrap_err(), TopoError::CycleDetected));
    }

    #[test]
    fn self_edge_rejected() {
        let mut t = TopoSort::new();
        t.add_node("a").unwrap();
        assert!(matches!(
            t.add_edge("a", "a").unwrap_err(),
            TopoError::SelfEdge(_)
        ));
    }

    #[test]
    fn unknown_endpoint_rejected() {
        let mut t = TopoSort::new();
        t.add_node("a").unwrap();
        assert!(matches!(
            t.add_edge("a", "b").unwrap_err(),
            TopoError::UnknownNode(_)
        ));
    }

    #[test]
    fn deterministic_ties() {
        // Two independent components — output should be sorted alphabetically.
        let mut t = TopoSort::new();
        for n in &["b", "a", "c"] {
            t.add_node(n).unwrap();
        }
        let s1 = t.sort().unwrap();
        assert_eq!(s1, vec!["a", "b", "c"]);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = TopoSort::new();
        t.schema_version = "9.9.9".into();
        assert!(matches!(
            t.validate().unwrap_err(),
            TopoError::SchemaMismatch
        ));
    }

    #[test]
    fn topo_serde_roundtrip() {
        let mut t = TopoSort::new();
        t.add_node("a").unwrap();
        t.add_node("b").unwrap();
        t.add_edge("a", "b").unwrap();
        let j = serde_json::to_string(&t).unwrap();
        let back: TopoSort = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
