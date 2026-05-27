//! `selfdef-action-dependency-graph` — action DAG.
//!
//! Actions form a directed acyclic graph (DAG) where `add_edge(
//! parent, child)` records that `child` depends on `parent`.
//! `topological_order()` returns a stable ordering (parents before
//! children, ties broken alphabetically) or `Err(Cycle)` if a cycle
//! would be introduced.
//!
//! `add_edge` itself refuses to introduce a cycle; the operation
//! returns `Err(WouldCycle)` and the graph is left unchanged.
//!
//! `parents_of(id)` / `children_of(id)` expose adjacency.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionDependencyGraph {
    /// Schema version.
    pub schema_version: String,
    /// All nodes.
    pub nodes: BTreeSet<String>,
    /// child → parents.
    pub parents: BTreeMap<String, BTreeSet<String>>,
    /// parent → children.
    pub children: BTreeMap<String, BTreeSet<String>>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum GraphError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("action id empty")]
    EmptyId,
    /// Self-loop.
    #[error("self-loop not allowed: {0}")]
    SelfLoop(String),
    /// Would create a cycle.
    #[error("edge {parent} -> {child} would create a cycle")]
    WouldCycle {
        /// parent.
        parent: String,
        /// child.
        child: String,
    },
    /// Cycle in graph (when computing order).
    #[error("graph contains a cycle")]
    Cycle,
}

impl ActionDependencyGraph {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            nodes: BTreeSet::new(),
            parents: BTreeMap::new(),
            children: BTreeMap::new(),
        }
    }

    /// Add a node.
    pub fn add_node(&mut self, id: &str) -> Result<bool, GraphError> {
        if id.is_empty() {
            return Err(GraphError::EmptyId);
        }
        Ok(self.nodes.insert(id.into()))
    }

    /// Add an edge parent → child.
    pub fn add_edge(&mut self, parent: &str, child: &str) -> Result<(), GraphError> {
        if parent.is_empty() || child.is_empty() {
            return Err(GraphError::EmptyId);
        }
        if parent == child {
            return Err(GraphError::SelfLoop(parent.into()));
        }
        // Insert nodes first (clean to roll back since we check cycle next).
        self.nodes.insert(parent.into());
        self.nodes.insert(child.into());
        // Check for cycle: would adding parent→child create a path child →* parent already?
        if self.reachable(child, parent) {
            return Err(GraphError::WouldCycle {
                parent: parent.into(),
                child: child.into(),
            });
        }
        self.children
            .entry(parent.into())
            .or_default()
            .insert(child.into());
        self.parents
            .entry(child.into())
            .or_default()
            .insert(parent.into());
        Ok(())
    }

    /// Reachability: is `to` reachable from `from`?
    fn reachable(&self, from: &str, to: &str) -> bool {
        if from == to {
            return true;
        }
        let mut q: VecDeque<&str> = VecDeque::new();
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        q.push_back(from);
        seen.insert(from);
        while let Some(n) = q.pop_front() {
            if n == to {
                return true;
            }
            if let Some(kids) = self.children.get(n) {
                for k in kids {
                    let s: &str = k.as_str();
                    if seen.insert(s) {
                        q.push_back(s);
                    }
                }
            }
        }
        false
    }

    /// Parents of a node.
    pub fn parents_of(&self, id: &str) -> Vec<String> {
        self.parents
            .get(id)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Children of a node.
    pub fn children_of(&self, id: &str) -> Vec<String> {
        self.children
            .get(id)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Topological order (Kahn's algorithm; alphabetical tie-break).
    pub fn topological_order(&self) -> Result<Vec<String>, GraphError> {
        let mut indeg: BTreeMap<String, usize> = BTreeMap::new();
        for n in &self.nodes {
            indeg.insert(n.clone(), self.parents.get(n).map(|p| p.len()).unwrap_or(0));
        }
        let mut order = Vec::with_capacity(self.nodes.len());
        loop {
            // Pick the alphabetically-smallest node with indeg 0.
            let next = indeg.iter().find(|&(_, &d)| d == 0).map(|(k, _)| k.clone());
            match next {
                Some(n) => {
                    order.push(n.clone());
                    indeg.remove(&n);
                    if let Some(kids) = self.children.get(&n) {
                        for c in kids {
                            if let Some(d) = indeg.get_mut(c) {
                                *d = d.saturating_sub(1);
                            }
                        }
                    }
                }
                None => break,
            }
        }
        if !indeg.is_empty() {
            return Err(GraphError::Cycle);
        }
        Ok(order)
    }

    /// Remove a node and all its edges.
    pub fn remove_node(&mut self, id: &str) -> bool {
        if !self.nodes.remove(id) {
            return false;
        }
        let parents = self.parents.remove(id).unwrap_or_default();
        for p in &parents {
            if let Some(set) = self.children.get_mut(p) {
                set.remove(id);
            }
        }
        let kids = self.children.remove(id).unwrap_or_default();
        for c in &kids {
            if let Some(set) = self.parents.get_mut(c) {
                set.remove(id);
            }
        }
        true
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), GraphError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(GraphError::SchemaMismatch);
        }
        for n in &self.nodes {
            if n.is_empty() {
                return Err(GraphError::EmptyId);
            }
        }
        Ok(())
    }
}

impl Default for ActionDependencyGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topological_simple() {
        let mut g = ActionDependencyGraph::new();
        g.add_edge("a", "b").unwrap();
        g.add_edge("b", "c").unwrap();
        let o = g.topological_order().unwrap();
        assert_eq!(o, vec!["a", "b", "c"]);
    }

    #[test]
    fn topological_alphabetical_tie_break() {
        let mut g = ActionDependencyGraph::new();
        g.add_node("a").unwrap();
        g.add_node("b").unwrap();
        // No edges — alphabetical order.
        let o = g.topological_order().unwrap();
        assert_eq!(o, vec!["a", "b"]);
    }

    #[test]
    fn would_cycle_rejected() {
        let mut g = ActionDependencyGraph::new();
        g.add_edge("a", "b").unwrap();
        g.add_edge("b", "c").unwrap();
        assert!(matches!(
            g.add_edge("c", "a").unwrap_err(),
            GraphError::WouldCycle { .. }
        ));
        // Graph still acyclic.
        assert!(g.topological_order().is_ok());
    }

    #[test]
    fn self_loop_rejected() {
        let mut g = ActionDependencyGraph::new();
        assert!(matches!(
            g.add_edge("a", "a").unwrap_err(),
            GraphError::SelfLoop(_)
        ));
    }

    #[test]
    fn parents_and_children_correct() {
        let mut g = ActionDependencyGraph::new();
        g.add_edge("a", "c").unwrap();
        g.add_edge("b", "c").unwrap();
        let mut p = g.parents_of("c");
        p.sort();
        assert_eq!(p, vec!["a", "b"]);
        assert_eq!(g.children_of("a"), vec!["c"]);
    }

    #[test]
    fn remove_node_cleans_edges() {
        let mut g = ActionDependencyGraph::new();
        g.add_edge("a", "b").unwrap();
        g.add_edge("b", "c").unwrap();
        assert!(g.remove_node("b"));
        assert!(g.parents_of("c").is_empty());
        assert!(g.children_of("a").is_empty());
    }

    #[test]
    fn diamond_topology() {
        let mut g = ActionDependencyGraph::new();
        //     a
        //    / \
        //   b   c
        //    \ /
        //     d
        g.add_edge("a", "b").unwrap();
        g.add_edge("a", "c").unwrap();
        g.add_edge("b", "d").unwrap();
        g.add_edge("c", "d").unwrap();
        let o = g.topological_order().unwrap();
        // a first, d last, b and c in between (alphabetical).
        assert_eq!(o[0], "a");
        assert_eq!(o[3], "d");
        assert!(o.contains(&"b".to_string()));
        assert!(o.contains(&"c".to_string()));
    }

    #[test]
    fn empty_id_rejected() {
        let mut g = ActionDependencyGraph::new();
        assert!(matches!(g.add_node("").unwrap_err(), GraphError::EmptyId));
        assert!(matches!(
            g.add_edge("", "x").unwrap_err(),
            GraphError::EmptyId
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut g = ActionDependencyGraph::new();
        g.schema_version = "9.9.9".into();
        assert!(matches!(
            g.validate().unwrap_err(),
            GraphError::SchemaMismatch
        ));
    }

    #[test]
    fn graph_serde_roundtrip() {
        let mut g = ActionDependencyGraph::new();
        g.add_edge("a", "b").unwrap();
        let j = serde_json::to_string(&g).unwrap();
        let back: ActionDependencyGraph = serde_json::from_str(&j).unwrap();
        assert_eq!(g, back);
    }
}
