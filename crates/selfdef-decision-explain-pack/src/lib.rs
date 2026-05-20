//! `selfdef-decision-explain-pack` — structured explanation per decision.
//!
//! `record(decision_id, outcome, rules_fired, rules_skipped, ts)`
//! captures everything a renderer needs to explain why a decision
//! came out the way it did. `fetch(decision_id)` returns the pack
//! or None.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One pack.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExplainPack {
    /// Final outcome label.
    pub outcome: String,
    /// Ordered rule ids that fired.
    pub rules_fired: Vec<String>,
    /// Ordered rule ids that were skipped (and why label).
    pub rules_skipped: Vec<(String, String)>,
    /// Captured ts.
    pub ts_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionExplainPack {
    /// Schema version.
    pub schema_version: String,
    /// decision_id → pack.
    pub packs: BTreeMap<String, ExplainPack>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ExplainError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty decision id.
    #[error("decision id empty")]
    EmptyDecisionId,
    /// Empty outcome.
    #[error("outcome empty")]
    EmptyOutcome,
}

impl DecisionExplainPack {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            packs: BTreeMap::new(),
        }
    }

    /// Record.
    pub fn record(
        &mut self,
        decision_id: &str,
        outcome: &str,
        rules_fired: Vec<String>,
        rules_skipped: Vec<(String, String)>,
        ts_ms: u64,
    ) -> Result<(), ExplainError> {
        if decision_id.is_empty() { return Err(ExplainError::EmptyDecisionId); }
        if outcome.is_empty() { return Err(ExplainError::EmptyOutcome); }
        self.packs.insert(decision_id.into(), ExplainPack {
            outcome: outcome.into(),
            rules_fired,
            rules_skipped,
            ts_ms,
        });
        Ok(())
    }

    /// Fetch.
    pub fn fetch(&self, decision_id: &str) -> Option<&ExplainPack> {
        self.packs.get(decision_id)
    }

    /// Drop packs older than retention_ms.
    pub fn rotate(&mut self, now_ms: u64, retention_ms: u64) {
        let cutoff = now_ms.saturating_sub(retention_ms);
        self.packs.retain(|_, p| p.ts_ms >= cutoff);
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ExplainError> {
        if self.schema_version != SCHEMA_VERSION { return Err(ExplainError::SchemaMismatch); }
        for (id, p) in &self.packs {
            if id.is_empty() { return Err(ExplainError::EmptyDecisionId); }
            if p.outcome.is_empty() { return Err(ExplainError::EmptyOutcome); }
        }
        Ok(())
    }
}

impl Default for DecisionExplainPack {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_fetch() {
        let mut e = DecisionExplainPack::new();
        e.record("dec-1", "Allow", vec!["rule-A".into(), "rule-B".into()],
            vec![("rule-C".into(), "out-of-scope".into())], 1000).unwrap();
        let p = e.fetch("dec-1").unwrap();
        assert_eq!(p.outcome, "Allow");
        assert_eq!(p.rules_fired.len(), 2);
        assert_eq!(p.rules_skipped[0], ("rule-C".into(), "out-of-scope".into()));
    }

    #[test]
    fn fetch_unknown_none() {
        let e = DecisionExplainPack::new();
        assert!(e.fetch("missing").is_none());
    }

    #[test]
    fn record_overwrites() {
        let mut e = DecisionExplainPack::new();
        e.record("dec-1", "Allow", vec![], vec![], 1000).unwrap();
        e.record("dec-1", "Deny", vec![], vec![], 2000).unwrap();
        assert_eq!(e.fetch("dec-1").unwrap().outcome, "Deny");
    }

    #[test]
    fn rotate_drops_old() {
        let mut e = DecisionExplainPack::new();
        e.record("dec-1", "Allow", vec![], vec![], 1000).unwrap();
        e.rotate(120_000, 60_000);
        assert!(e.fetch("dec-1").is_none());
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut e = DecisionExplainPack::new();
        assert!(matches!(e.record("", "x", vec![], vec![], 0).unwrap_err(), ExplainError::EmptyDecisionId));
        assert!(matches!(e.record("d", "", vec![], vec![], 0).unwrap_err(), ExplainError::EmptyOutcome));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut e = DecisionExplainPack::new();
        e.schema_version = "9.9.9".into();
        assert!(matches!(e.validate().unwrap_err(), ExplainError::SchemaMismatch));
    }

    #[test]
    fn pack_serde_roundtrip() {
        let mut e = DecisionExplainPack::new();
        e.record("dec-1", "Allow", vec!["r1".into()], vec![("r2".into(), "skip".into())], 1000).unwrap();
        let j = serde_json::to_string(&e).unwrap();
        let back: DecisionExplainPack = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }
}
