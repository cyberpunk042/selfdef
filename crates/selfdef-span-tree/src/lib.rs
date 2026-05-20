//! `selfdef-span-tree` — trace span hierarchy.
//!
//! Span{id, parent (None=root), name, start_ms, end_ms}.
//! insert(span) rejects duplicates + unknown parents + cycles.
//! root() returns the single root id (None if zero, error if
//! multiple). children(id) / descendants(id) / total_duration.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Span.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Span {
    /// Id.
    pub id: String,
    /// Parent id (None = root).
    pub parent: Option<String>,
    /// Name.
    pub name: String,
    /// Start ms.
    pub start_ms: u64,
    /// End ms.
    pub end_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpanTree {
    /// Schema version.
    pub schema_version: String,
    /// id → span.
    pub spans: BTreeMap<String, Span>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SpanError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("id empty")]
    EmptyId,
    /// Empty.
    #[error("name empty")]
    EmptyName,
    /// Bad times.
    #[error("start_ms > end_ms")]
    BadTimes,
    /// Duplicate.
    #[error("duplicate span: {0}")]
    DuplicateSpan(String),
    /// Unknown parent.
    #[error("unknown parent: {0}")]
    UnknownParent(String),
    /// Multiple roots.
    #[error("multiple roots")]
    MultipleRoots,
}

impl SpanTree {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            spans: BTreeMap::new(),
        }
    }

    /// Insert.
    pub fn insert(&mut self, id: &str, parent: Option<&str>, name: &str, start_ms: u64, end_ms: u64) -> Result<(), SpanError> {
        if id.is_empty() { return Err(SpanError::EmptyId); }
        if name.is_empty() { return Err(SpanError::EmptyName); }
        if start_ms > end_ms { return Err(SpanError::BadTimes); }
        if self.spans.contains_key(id) { return Err(SpanError::DuplicateSpan(id.into())); }
        if let Some(p) = parent {
            if !self.spans.contains_key(p) {
                return Err(SpanError::UnknownParent(p.into()));
            }
        }
        self.spans.insert(id.into(), Span {
            id: id.into(),
            parent: parent.map(|s| s.to_string()),
            name: name.into(),
            start_ms,
            end_ms,
        });
        Ok(())
    }

    /// Find root (exactly one expected).
    pub fn root(&self) -> Result<Option<&str>, SpanError> {
        let roots: Vec<&str> = self.spans.values()
            .filter(|s| s.parent.is_none())
            .map(|s| s.id.as_str())
            .collect();
        match roots.len() {
            0 => Ok(None),
            1 => Ok(Some(roots[0])),
            _ => Err(SpanError::MultipleRoots),
        }
    }

    /// Direct children of a span.
    pub fn children(&self, id: &str) -> Vec<&Span> {
        self.spans.values()
            .filter(|s| s.parent.as_deref() == Some(id))
            .collect()
    }

    /// Recursive descendants.
    pub fn descendants(&self, id: &str) -> Vec<&Span> {
        let mut out = Vec::new();
        let mut stack: Vec<String> = self.children(id).iter().map(|s| s.id.clone()).collect();
        while let Some(cur) = stack.pop() {
            if let Some(s) = self.spans.get(&cur) {
                out.push(s);
                for child in self.children(&cur) {
                    stack.push(child.id.clone());
                }
            }
        }
        out
    }

    /// Total duration ms across all spans (sum of end-start).
    pub fn total_duration_ms(&self) -> u128 {
        self.spans.values()
            .map(|s| (s.end_ms - s.start_ms) as u128)
            .sum()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), SpanError> {
        if self.schema_version != SCHEMA_VERSION { return Err(SpanError::SchemaMismatch); }
        for s in self.spans.values() {
            if s.id.is_empty() { return Err(SpanError::EmptyId); }
            if s.name.is_empty() { return Err(SpanError::EmptyName); }
            if s.start_ms > s.end_ms { return Err(SpanError::BadTimes); }
            if let Some(p) = &s.parent {
                if !self.spans.contains_key(p) { return Err(SpanError::UnknownParent(p.clone())); }
            }
        }
        Ok(())
    }
}

impl Default for SpanTree {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root_none() {
        let t = SpanTree::new();
        assert_eq!(t.root().unwrap(), None);
    }

    #[test]
    fn single_root() {
        let mut t = SpanTree::new();
        t.insert("a", None, "request", 0, 100).unwrap();
        assert_eq!(t.root().unwrap(), Some("a"));
    }

    #[test]
    fn children_and_descendants() {
        let mut t = SpanTree::new();
        t.insert("a", None, "req", 0, 1000).unwrap();
        t.insert("b", Some("a"), "db", 100, 200).unwrap();
        t.insert("c", Some("a"), "cache", 100, 150).unwrap();
        t.insert("d", Some("b"), "query", 110, 190).unwrap();
        assert_eq!(t.children("a").len(), 2);
        assert_eq!(t.descendants("a").len(), 3);
    }

    #[test]
    fn multiple_roots_error() {
        let mut t = SpanTree::new();
        t.insert("a", None, "r1", 0, 10).unwrap();
        t.insert("b", None, "r2", 0, 10).unwrap();
        assert!(matches!(t.root().unwrap_err(), SpanError::MultipleRoots));
    }

    #[test]
    fn unknown_parent_rejected() {
        let mut t = SpanTree::new();
        assert!(matches!(t.insert("a", Some("nope"), "x", 0, 1).unwrap_err(), SpanError::UnknownParent(_)));
    }

    #[test]
    fn duplicate_id_rejected() {
        let mut t = SpanTree::new();
        t.insert("a", None, "x", 0, 1).unwrap();
        assert!(matches!(t.insert("a", None, "y", 0, 1).unwrap_err(), SpanError::DuplicateSpan(_)));
    }

    #[test]
    fn bad_times_rejected() {
        let mut t = SpanTree::new();
        assert!(matches!(t.insert("a", None, "x", 100, 50).unwrap_err(), SpanError::BadTimes));
    }

    #[test]
    fn total_duration() {
        let mut t = SpanTree::new();
        t.insert("a", None, "r", 0, 100).unwrap();
        t.insert("b", Some("a"), "x", 0, 30).unwrap();
        assert_eq!(t.total_duration_ms(), 130);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = SpanTree::new();
        t.schema_version = "9.9.9".into();
        assert!(matches!(t.validate().unwrap_err(), SpanError::SchemaMismatch));
    }

    #[test]
    fn tree_serde_roundtrip() {
        let mut t = SpanTree::new();
        t.insert("a", None, "r", 0, 100).unwrap();
        let j = serde_json::to_string(&t).unwrap();
        let back: SpanTree = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
