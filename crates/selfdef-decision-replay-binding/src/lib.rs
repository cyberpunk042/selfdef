//! `selfdef-decision-replay-binding` — decision↔replay registry.
//!
//! Pairs a decision_id with a replay_slot_id so the cockpit /
//! audit can jump from a verdict to its replay artifacts.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One binding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Binding {
    /// Decision id.
    pub decision_id: String,
    /// Replay slot id.
    pub replay_slot_id: String,
    /// ISO-8601 UTC when bound.
    pub bound_at: String,
}

/// Registry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionReplayBinding {
    /// Schema version.
    pub schema_version: String,
    /// Bindings.
    pub bindings: Vec<Binding>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BindingError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty decision id.
    #[error("decision_id empty")]
    EmptyDecisionId,
    /// Empty replay slot id.
    #[error("replay_slot_id empty")]
    EmptyReplaySlotId,
    /// Decision already bound.
    #[error("decision_id {0} already bound")]
    AlreadyBound(String),
    /// Decision id not bound.
    #[error("decision_id {0} not bound")]
    NotBound(String),
}

impl DecisionReplayBinding {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            bindings: Vec::new(),
        }
    }

    /// Bind a decision to a replay slot.
    pub fn bind(&mut self, decision_id: &str, replay_slot_id: &str, at: &str) -> Result<(), BindingError> {
        if decision_id.is_empty() { return Err(BindingError::EmptyDecisionId); }
        if replay_slot_id.is_empty() { return Err(BindingError::EmptyReplaySlotId); }
        if self.bindings.iter().any(|b| b.decision_id == decision_id) {
            return Err(BindingError::AlreadyBound(decision_id.into()));
        }
        self.bindings.push(Binding {
            decision_id: decision_id.into(),
            replay_slot_id: replay_slot_id.into(),
            bound_at: at.into(),
        });
        Ok(())
    }

    /// Unbind a decision.
    pub fn unbind(&mut self, decision_id: &str) -> Result<(), BindingError> {
        let pos = self.bindings.iter().position(|b| b.decision_id == decision_id)
            .ok_or_else(|| BindingError::NotBound(decision_id.into()))?;
        self.bindings.remove(pos);
        Ok(())
    }

    /// Lookup decision → replay slot.
    pub fn lookup(&self, decision_id: &str) -> Option<&str> {
        self.bindings.iter().find(|b| b.decision_id == decision_id).map(|b| b.replay_slot_id.as_str())
    }

    /// Reverse lookup: replay slot → decision ids.
    pub fn decisions_for_slot(&self, replay_slot_id: &str) -> Vec<&str> {
        self.bindings.iter()
            .filter(|b| b.replay_slot_id == replay_slot_id)
            .map(|b| b.decision_id.as_str())
            .collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BindingError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BindingError::SchemaMismatch);
        }
        use std::collections::HashSet;
        let mut seen: HashSet<&str> = HashSet::new();
        for b in &self.bindings {
            if b.decision_id.is_empty() { return Err(BindingError::EmptyDecisionId); }
            if b.replay_slot_id.is_empty() { return Err(BindingError::EmptyReplaySlotId); }
            if !seen.insert(b.decision_id.as_str()) {
                return Err(BindingError::AlreadyBound(b.decision_id.clone()));
            }
        }
        Ok(())
    }
}

impl Default for DecisionReplayBinding {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_lookup() {
        let mut r = DecisionReplayBinding::new();
        r.bind("d1", "slot-a", "t").unwrap();
        assert_eq!(r.lookup("d1"), Some("slot-a"));
    }

    #[test]
    fn lookup_missing_returns_none() {
        let r = DecisionReplayBinding::new();
        assert!(r.lookup("d1").is_none());
    }

    #[test]
    fn bind_duplicate_rejected() {
        let mut r = DecisionReplayBinding::new();
        r.bind("d1", "slot-a", "t").unwrap();
        assert!(matches!(r.bind("d1", "slot-b", "t").unwrap_err(), BindingError::AlreadyBound(_)));
    }

    #[test]
    fn unbind_works() {
        let mut r = DecisionReplayBinding::new();
        r.bind("d1", "slot-a", "t").unwrap();
        r.unbind("d1").unwrap();
        assert!(r.lookup("d1").is_none());
    }

    #[test]
    fn unbind_missing_rejected() {
        let mut r = DecisionReplayBinding::new();
        assert!(matches!(r.unbind("d1").unwrap_err(), BindingError::NotBound(_)));
    }

    #[test]
    fn multiple_decisions_to_one_slot() {
        let mut r = DecisionReplayBinding::new();
        r.bind("d1", "slot-a", "t").unwrap();
        r.bind("d2", "slot-a", "t").unwrap();
        r.bind("d3", "slot-b", "t").unwrap();
        let a = r.decisions_for_slot("slot-a");
        assert_eq!(a.len(), 2);
        assert!(a.contains(&"d1"));
        assert!(a.contains(&"d2"));
    }

    #[test]
    fn empty_decision_id_rejected() {
        let mut r = DecisionReplayBinding::new();
        assert!(matches!(r.bind("", "slot", "t").unwrap_err(), BindingError::EmptyDecisionId));
    }

    #[test]
    fn empty_slot_id_rejected() {
        let mut r = DecisionReplayBinding::new();
        assert!(matches!(r.bind("d1", "", "t").unwrap_err(), BindingError::EmptyReplaySlotId));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = DecisionReplayBinding::new();
        r.schema_version = "9.9.9".into();
        assert!(matches!(r.validate().unwrap_err(), BindingError::SchemaMismatch));
    }

    #[test]
    fn registry_serde_roundtrip() {
        let mut r = DecisionReplayBinding::new();
        r.bind("d1", "slot-a", "t").unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: DecisionReplayBinding = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
