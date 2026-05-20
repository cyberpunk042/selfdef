//! `selfdef-dependency-resolver` — topo-order with cycle detect.
//!
//! add(id, deps[]) registers a node. resolve(target) computes
//! the resolve-order ending with target (Kahn over the reachable
//! sub-DAG); errors Cycle / Missing. resolve_all() resolves the
//! full graph.
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
pub struct DependencyResolver {
    /// Schema version.
    pub schema_version: String,
    /// id → deps.
    pub nodes: BTreeMap<String, BTreeSet<String>>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DepError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("id empty")]
    EmptyId,
    /// Duplicate.
    #[error("duplicate node: {0}")]
    DuplicateNode(String),
    /// Missing.
    #[error("missing dependency: {0}")]
    Missing(String),
    /// Cycle.
    #[error("cycle detected")]
    Cycle,
}

impl DependencyResolver {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            nodes: BTreeMap::new(),
        }
    }

    /// Register a node.
    pub fn add(&mut self, id: &str, deps: Vec<String>) -> Result<(), DepError> {
        if id.is_empty() { return Err(DepError::EmptyId); }
        for d in &deps {
            if d.is_empty() { return Err(DepError::EmptyId); }
        }
        if self.nodes.contains_key(id) { return Err(DepError::DuplicateNode(id.into())); }
        self.nodes.insert(id.into(), deps.into_iter().collect());
        Ok(())
    }

    /// Resolve the order ending with `target`.
    pub fn resolve(&self, target: &str) -> Result<Vec<String>, DepError> {
        if !self.nodes.contains_key(target) {
            return Err(DepError::Missing(target.into()));
        }
        // Collect reachable ids from target.
        let mut reachable: BTreeSet<String> = BTreeSet::new();
        let mut stack = vec![target.to_string()];
        while let Some(id) = stack.pop() {
            if !reachable.insert(id.clone()) { continue; }
            let deps = self.nodes.get(&id).ok_or_else(|| DepError::Missing(id.clone()))?;
            for d in deps {
                if !self.nodes.contains_key(d) {
                    return Err(DepError::Missing(d.clone()));
                }
                if !reachable.contains(d) { stack.push(d.clone()); }
            }
        }
        // Kahn over reachable set.
        let mut indegree: BTreeMap<String, u32> = reachable.iter().map(|k| (k.clone(), 0)).collect();
        for id in &reachable {
            for d in self.nodes.get(id).unwrap() {
                // edge: d → id; indegree of id increases.
                *indegree.get_mut(id).unwrap() += 1;
                // Note: only count edges within reachable (all deps reachable here).
                let _ = d;
            }
        }
        let mut ready: BTreeSet<String> = indegree.iter().filter(|&(_, &d)| d == 0).map(|(k, _)| k.clone()).collect();
        let mut out: Vec<String> = Vec::new();
        while let Some(n) = ready.iter().next().cloned() {
            ready.remove(&n);
            out.push(n.clone());
            // Iterate over reachable nodes whose deps include n.
            for m in reachable.iter() {
                let deps = self.nodes.get(m).unwrap();
                if deps.contains(&n) {
                    let d = indegree.get_mut(m).unwrap();
                    if *d > 0 { *d -= 1; }
                    if *d == 0 && m != &n && !out.iter().any(|x| x == m) {
                        ready.insert(m.clone());
                    }
                }
            }
        }
        if out.len() != reachable.len() {
            return Err(DepError::Cycle);
        }
        Ok(out)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DepError> {
        if self.schema_version != SCHEMA_VERSION { return Err(DepError::SchemaMismatch); }
        for (id, deps) in &self.nodes {
            if id.is_empty() { return Err(DepError::EmptyId); }
            for d in deps {
                if d.is_empty() { return Err(DepError::EmptyId); }
            }
        }
        Ok(())
    }
}

impl Default for DependencyResolver {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_chain() {
        let mut r = DependencyResolver::new();
        r.add("a", vec![]).unwrap();
        r.add("b", vec!["a".into()]).unwrap();
        r.add("c", vec!["b".into()]).unwrap();
        assert_eq!(r.resolve("c").unwrap(), vec!["a", "b", "c"]);
    }

    #[test]
    fn diamond() {
        let mut r = DependencyResolver::new();
        r.add("a", vec![]).unwrap();
        r.add("b", vec!["a".into()]).unwrap();
        r.add("c", vec!["a".into()]).unwrap();
        r.add("d", vec!["b".into(), "c".into()]).unwrap();
        let order = r.resolve("d").unwrap();
        let pos = |x: &str| order.iter().position(|y| y == x).unwrap();
        assert!(pos("a") < pos("b"));
        assert!(pos("a") < pos("c"));
        assert!(pos("b") < pos("d"));
        assert!(pos("c") < pos("d"));
    }

    #[test]
    fn missing_dep_rejected() {
        let mut r = DependencyResolver::new();
        r.add("a", vec!["nope".into()]).unwrap();
        assert!(matches!(r.resolve("a").unwrap_err(), DepError::Missing(_)));
    }

    #[test]
    fn cycle_detected() {
        let mut r = DependencyResolver::new();
        r.add("a", vec!["b".into()]).unwrap();
        r.add("b", vec!["a".into()]).unwrap();
        assert!(matches!(r.resolve("a").unwrap_err(), DepError::Cycle));
    }

    #[test]
    fn unknown_target_rejected() {
        let r = DependencyResolver::new();
        assert!(matches!(r.resolve("nope").unwrap_err(), DepError::Missing(_)));
    }

    #[test]
    fn empty_id_rejected() {
        let mut r = DependencyResolver::new();
        assert!(matches!(r.add("", vec![]).unwrap_err(), DepError::EmptyId));
        assert!(matches!(r.add("a", vec!["".into()]).unwrap_err(), DepError::EmptyId));
    }

    #[test]
    fn duplicate_node_rejected() {
        let mut r = DependencyResolver::new();
        r.add("a", vec![]).unwrap();
        assert!(matches!(r.add("a", vec![]).unwrap_err(), DepError::DuplicateNode(_)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = DependencyResolver::new();
        r.schema_version = "9.9.9".into();
        assert!(matches!(r.validate().unwrap_err(), DepError::SchemaMismatch));
    }

    #[test]
    fn resolver_serde_roundtrip() {
        let mut r = DependencyResolver::new();
        r.add("a", vec![]).unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: DependencyResolver = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
