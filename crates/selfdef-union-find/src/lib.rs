//! `selfdef-union-find` — disjoint-set union with rank + path compression.
//!
//! add(id) registers an element. union(a, b) joins their sets
//! using rank. find(id) returns the root after path compression.
//! component_size(id) returns root's set size.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-element entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// Parent id (self if root).
    pub parent: String,
    /// Rank (height upper bound).
    pub rank: u32,
    /// Set size (valid only at root).
    pub size: u32,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnionFind {
    /// Schema version.
    pub schema_version: String,
    /// id → entry.
    pub entries: BTreeMap<String, Entry>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum UfError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("id empty")]
    EmptyId,
    /// Duplicate.
    #[error("duplicate id: {0}")]
    DuplicateId(String),
    /// Unknown.
    #[error("unknown id: {0}")]
    UnknownId(String),
}

impl UnionFind {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            entries: BTreeMap::new(),
        }
    }

    /// Add element (as a singleton).
    pub fn add(&mut self, id: &str) -> Result<(), UfError> {
        if id.is_empty() {
            return Err(UfError::EmptyId);
        }
        if self.entries.contains_key(id) {
            return Err(UfError::DuplicateId(id.into()));
        }
        self.entries.insert(
            id.into(),
            Entry {
                parent: id.into(),
                rank: 0,
                size: 1,
            },
        );
        Ok(())
    }

    /// Find root with path compression.
    pub fn find(&mut self, id: &str) -> Result<String, UfError> {
        if !self.entries.contains_key(id) {
            return Err(UfError::UnknownId(id.into()));
        }
        // Walk up.
        let mut cur = id.to_string();
        let mut path: Vec<String> = Vec::new();
        loop {
            let parent = self.entries.get(&cur).unwrap().parent.clone();
            if parent == cur {
                break;
            }
            path.push(cur.clone());
            cur = parent;
        }
        let root = cur;
        // Path-compress.
        for n in path {
            self.entries.get_mut(&n).unwrap().parent = root.clone();
        }
        Ok(root)
    }

    /// Union two elements (by rank).
    pub fn union(&mut self, a: &str, b: &str) -> Result<(), UfError> {
        let ra = self.find(a)?;
        let rb = self.find(b)?;
        if ra == rb {
            return Ok(());
        }
        let rank_a = self.entries.get(&ra).unwrap().rank;
        let rank_b = self.entries.get(&rb).unwrap().rank;
        let size_a = self.entries.get(&ra).unwrap().size;
        let size_b = self.entries.get(&rb).unwrap().size;
        let (root, child) = if rank_a < rank_b {
            (rb.clone(), ra.clone())
        } else {
            // a wins on higher-or-equal rank (ties: a wins, bump rank)
            (ra.clone(), rb.clone())
        };
        self.entries.get_mut(&child).unwrap().parent = root.clone();
        self.entries.get_mut(&root).unwrap().size = size_a.saturating_add(size_b);
        if rank_a == rank_b {
            self.entries.get_mut(&root).unwrap().rank = rank_a.saturating_add(1);
        }
        Ok(())
    }

    /// Set size for id's component.
    pub fn component_size(&mut self, id: &str) -> Result<u32, UfError> {
        let root = self.find(id)?;
        Ok(self.entries.get(&root).unwrap().size)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), UfError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(UfError::SchemaMismatch);
        }
        for (id, e) in &self.entries {
            if id.is_empty() {
                return Err(UfError::EmptyId);
            }
            if !self.entries.contains_key(&e.parent) {
                return Err(UfError::UnknownId(e.parent.clone()));
            }
        }
        Ok(())
    }
}

impl Default for UnionFind {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn singletons_separate() {
        let mut u = UnionFind::new();
        u.add("a").unwrap();
        u.add("b").unwrap();
        assert_ne!(u.find("a").unwrap(), u.find("b").unwrap());
    }

    #[test]
    fn union_joins() {
        let mut u = UnionFind::new();
        u.add("a").unwrap();
        u.add("b").unwrap();
        u.union("a", "b").unwrap();
        assert_eq!(u.find("a").unwrap(), u.find("b").unwrap());
    }

    #[test]
    fn component_size_grows() {
        let mut u = UnionFind::new();
        u.add("a").unwrap();
        u.add("b").unwrap();
        u.add("c").unwrap();
        u.union("a", "b").unwrap();
        u.union("b", "c").unwrap();
        assert_eq!(u.component_size("a").unwrap(), 3);
        assert_eq!(u.component_size("b").unwrap(), 3);
        assert_eq!(u.component_size("c").unwrap(), 3);
    }

    #[test]
    fn union_idempotent() {
        let mut u = UnionFind::new();
        u.add("a").unwrap();
        u.add("b").unwrap();
        u.union("a", "b").unwrap();
        u.union("a", "b").unwrap();
        assert_eq!(u.component_size("a").unwrap(), 2);
    }

    #[test]
    fn duplicate_add_rejected() {
        let mut u = UnionFind::new();
        u.add("a").unwrap();
        assert!(matches!(u.add("a").unwrap_err(), UfError::DuplicateId(_)));
    }

    #[test]
    fn unknown_find_rejected() {
        let mut u = UnionFind::new();
        assert!(matches!(u.find("nope").unwrap_err(), UfError::UnknownId(_)));
    }

    #[test]
    fn empty_id_rejected() {
        let mut u = UnionFind::new();
        assert!(matches!(u.add("").unwrap_err(), UfError::EmptyId));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut u = UnionFind::new();
        u.schema_version = "9.9.9".into();
        assert!(matches!(u.validate().unwrap_err(), UfError::SchemaMismatch));
    }

    #[test]
    fn uf_serde_roundtrip() {
        let mut u = UnionFind::new();
        u.add("a").unwrap();
        u.add("b").unwrap();
        u.union("a", "b").unwrap();
        let j = serde_json::to_string(&u).unwrap();
        let back: UnionFind = serde_json::from_str(&j).unwrap();
        assert_eq!(u, back);
    }
}
