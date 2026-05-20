//! `selfdef-correlation-id-issuer` — request correlation IDs.
//!
//! `issue(parent, ts)` returns a new id and links it to parent
//! (None for root). `lineage(id)` returns the parent chain root→
//! id. IDs are monotonic u64.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One correlation node.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Node {
    /// Id.
    pub id: u64,
    /// Parent (None = root).
    pub parent: Option<u64>,
    /// Created.
    pub created_at_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorrelationIdIssuer {
    /// Schema version.
    pub schema_version: String,
    /// id → node.
    pub nodes: BTreeMap<u64, Node>,
    /// Next id.
    pub next_id: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CorrError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Unknown parent.
    #[error("unknown parent: {0}")]
    UnknownParent(u64),
}

impl CorrelationIdIssuer {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            nodes: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Issue.
    pub fn issue(&mut self, parent: Option<u64>, ts_ms: u64) -> Result<u64, CorrError> {
        if let Some(p) = parent {
            if !self.nodes.contains_key(&p) {
                return Err(CorrError::UnknownParent(p));
            }
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.nodes.insert(id, Node { id, parent, created_at_ms: ts_ms });
        Ok(id)
    }

    /// Get.
    pub fn get(&self, id: u64) -> Option<Node> {
        self.nodes.get(&id).copied()
    }

    /// Lineage root→id.
    pub fn lineage(&self, id: u64) -> Vec<u64> {
        let mut chain = Vec::new();
        let mut cur = Some(id);
        let mut seen = std::collections::BTreeSet::new();
        while let Some(c) = cur {
            if !seen.insert(c) { break; }
            chain.push(c);
            cur = self.nodes.get(&c).and_then(|n| n.parent);
        }
        chain.reverse();
        chain
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CorrError> {
        if self.schema_version != SCHEMA_VERSION { return Err(CorrError::SchemaMismatch); }
        for n in self.nodes.values() {
            if let Some(p) = n.parent {
                if !self.nodes.contains_key(&p) { return Err(CorrError::UnknownParent(p)); }
            }
        }
        Ok(())
    }
}

impl Default for CorrelationIdIssuer {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_root_then_child() {
        let mut c = CorrelationIdIssuer::new();
        let root = c.issue(None, 0).unwrap();
        let child = c.issue(Some(root), 100).unwrap();
        assert_eq!(c.lineage(child), vec![root, child]);
    }

    #[test]
    fn lineage_root_only() {
        let mut c = CorrelationIdIssuer::new();
        let r = c.issue(None, 0).unwrap();
        assert_eq!(c.lineage(r), vec![r]);
    }

    #[test]
    fn lineage_deep() {
        let mut c = CorrelationIdIssuer::new();
        let a = c.issue(None, 0).unwrap();
        let b = c.issue(Some(a), 0).unwrap();
        let cc = c.issue(Some(b), 0).unwrap();
        assert_eq!(c.lineage(cc), vec![a, b, cc]);
    }

    #[test]
    fn unknown_parent_rejected() {
        let mut c = CorrelationIdIssuer::new();
        assert!(matches!(c.issue(Some(999), 0).unwrap_err(), CorrError::UnknownParent(_)));
    }

    #[test]
    fn ids_monotonic() {
        let mut c = CorrelationIdIssuer::new();
        let a = c.issue(None, 0).unwrap();
        let b = c.issue(None, 0).unwrap();
        assert_eq!(b, a + 1);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = CorrelationIdIssuer::new();
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), CorrError::SchemaMismatch));
    }

    #[test]
    fn corr_serde_roundtrip() {
        let mut c = CorrelationIdIssuer::new();
        c.issue(None, 0).unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: CorrelationIdIssuer = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
