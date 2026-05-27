//! `selfdef-ranking-table` — id→score with top-N + rank.
//!
//! set(id, score) registers or updates. top_n returns up to N
//! (id, score) sorted by score desc + id asc. rank_of(id) is
//! the 1-based position in the sorted order, or None if absent.
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
pub struct RankingTable {
    /// Schema version.
    pub schema_version: String,
    /// id → score.
    pub scores: BTreeMap<String, i64>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RankError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("id empty")]
    EmptyId,
}

impl RankingTable {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            scores: BTreeMap::new(),
        }
    }

    /// Set score (insert or overwrite).
    pub fn set(&mut self, id: &str, score: i64) -> Result<(), RankError> {
        if id.is_empty() {
            return Err(RankError::EmptyId);
        }
        self.scores.insert(id.into(), score);
        Ok(())
    }

    /// Remove by id.
    pub fn remove(&mut self, id: &str) -> bool {
        self.scores.remove(id).is_some()
    }

    /// Sorted (id, score) by score desc + id asc.
    fn sorted(&self) -> Vec<(String, i64)> {
        let mut all: Vec<(String, i64)> =
            self.scores.iter().map(|(k, v)| (k.clone(), *v)).collect();
        all.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        all
    }

    /// Top N.
    pub fn top_n(&self, n: usize) -> Vec<(String, i64)> {
        self.sorted().into_iter().take(n).collect()
    }

    /// 1-based rank (None if absent).
    pub fn rank_of(&self, id: &str) -> Option<u32> {
        if !self.scores.contains_key(id) {
            return None;
        }
        let sorted = self.sorted();
        sorted
            .iter()
            .position(|(k, _)| k == id)
            .map(|i| (i + 1) as u32)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RankError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RankError::SchemaMismatch);
        }
        for k in self.scores.keys() {
            if k.is_empty() {
                return Err(RankError::EmptyId);
            }
        }
        Ok(())
    }
}

impl Default for RankingTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_top() {
        let mut t = RankingTable::new();
        t.set("a", 5).unwrap();
        t.set("b", 10).unwrap();
        t.set("c", 2).unwrap();
        let top = t.top_n(2);
        assert_eq!(top, vec![("b".into(), 10), ("a".into(), 5)]);
    }

    #[test]
    fn ties_lex_asc() {
        let mut t = RankingTable::new();
        t.set("b", 5).unwrap();
        t.set("a", 5).unwrap();
        let top = t.top_n(2);
        assert_eq!(top[0].0, "a");
        assert_eq!(top[1].0, "b");
    }

    #[test]
    fn rank_of_known() {
        let mut t = RankingTable::new();
        t.set("a", 5).unwrap();
        t.set("b", 10).unwrap();
        t.set("c", 2).unwrap();
        assert_eq!(t.rank_of("b"), Some(1));
        assert_eq!(t.rank_of("a"), Some(2));
        assert_eq!(t.rank_of("c"), Some(3));
        assert_eq!(t.rank_of("missing"), None);
    }

    #[test]
    fn remove_clears_rank() {
        let mut t = RankingTable::new();
        t.set("a", 5).unwrap();
        assert!(t.remove("a"));
        assert!(t.rank_of("a").is_none());
    }

    #[test]
    fn negative_scores() {
        let mut t = RankingTable::new();
        t.set("a", -10).unwrap();
        t.set("b", -5).unwrap();
        assert_eq!(t.top_n(2)[0].0, "b");
    }

    #[test]
    fn empty_id_rejected() {
        let mut t = RankingTable::new();
        assert!(matches!(t.set("", 1).unwrap_err(), RankError::EmptyId));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = RankingTable::new();
        t.schema_version = "9.9.9".into();
        assert!(matches!(
            t.validate().unwrap_err(),
            RankError::SchemaMismatch
        ));
    }

    #[test]
    fn table_serde_roundtrip() {
        let mut t = RankingTable::new();
        t.set("a", 5).unwrap();
        let j = serde_json::to_string(&t).unwrap();
        let back: RankingTable = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
