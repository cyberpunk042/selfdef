//! `selfdef-policy-test-harness` — record/replay decisions.
//!
//! Case{id, input, expected_outcome}. record_observed appends to
//! a case the actually-observed outcome. summary() returns
//! Summary{total, passed, failed, mismatches:Vec<id>}.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One test case.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Case {
    /// Id.
    pub id: String,
    /// Input payload.
    pub input: String,
    /// Expected outcome label.
    pub expected_outcome: String,
    /// Last observed outcome.
    pub observed_outcome: Option<String>,
}

/// Summary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Summary {
    /// Total cases.
    pub total: u32,
    /// Cases passed.
    pub passed: u32,
    /// Cases failed.
    pub failed: u32,
    /// Cases not yet run.
    pub unrun: u32,
    /// Failing ids.
    pub mismatches: Vec<String>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyTestHarness {
    /// Schema version.
    pub schema_version: String,
    /// id → case.
    pub cases: BTreeMap<String, Case>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum HarnessError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("id empty")]
    EmptyId,
    /// Empty.
    #[error("expected outcome empty")]
    EmptyExpected,
    /// Duplicate.
    #[error("duplicate case id: {0}")]
    DuplicateId(String),
    /// Unknown.
    #[error("unknown case: {0}")]
    UnknownCase(String),
}

impl PolicyTestHarness {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            cases: BTreeMap::new(),
        }
    }

    /// Add case.
    pub fn add_case(&mut self, id: &str, input: &str, expected_outcome: &str) -> Result<(), HarnessError> {
        if id.is_empty() { return Err(HarnessError::EmptyId); }
        if expected_outcome.is_empty() { return Err(HarnessError::EmptyExpected); }
        if self.cases.contains_key(id) { return Err(HarnessError::DuplicateId(id.into())); }
        self.cases.insert(id.into(), Case {
            id: id.into(),
            input: input.into(),
            expected_outcome: expected_outcome.into(),
            observed_outcome: None,
        });
        Ok(())
    }

    /// Record observed outcome.
    pub fn record_observed(&mut self, id: &str, observed: &str) -> Result<(), HarnessError> {
        let c = self.cases.get_mut(id).ok_or_else(|| HarnessError::UnknownCase(id.into()))?;
        c.observed_outcome = Some(observed.into());
        Ok(())
    }

    /// Reset observations.
    pub fn reset_observed(&mut self) {
        for c in self.cases.values_mut() {
            c.observed_outcome = None;
        }
    }

    /// Summary.
    pub fn summary(&self) -> Summary {
        let mut s = Summary {
            total: self.cases.len() as u32,
            passed: 0,
            failed: 0,
            unrun: 0,
            mismatches: Vec::new(),
        };
        for c in self.cases.values() {
            match &c.observed_outcome {
                None => s.unrun = s.unrun.saturating_add(1),
                Some(o) if *o == c.expected_outcome => s.passed = s.passed.saturating_add(1),
                Some(_) => {
                    s.failed = s.failed.saturating_add(1);
                    s.mismatches.push(c.id.clone());
                }
            }
        }
        s
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), HarnessError> {
        if self.schema_version != SCHEMA_VERSION { return Err(HarnessError::SchemaMismatch); }
        for (id, c) in &self.cases {
            if id.is_empty() { return Err(HarnessError::EmptyId); }
            if c.expected_outcome.is_empty() { return Err(HarnessError::EmptyExpected); }
        }
        Ok(())
    }
}

impl Default for PolicyTestHarness {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_pass_when_observations_match() {
        let mut h = PolicyTestHarness::new();
        h.add_case("a", "in", "allow").unwrap();
        h.add_case("b", "in", "deny").unwrap();
        h.record_observed("a", "allow").unwrap();
        h.record_observed("b", "deny").unwrap();
        let s = h.summary();
        assert_eq!(s.passed, 2);
        assert_eq!(s.failed, 0);
    }

    #[test]
    fn mismatch_recorded() {
        let mut h = PolicyTestHarness::new();
        h.add_case("a", "in", "allow").unwrap();
        h.record_observed("a", "deny").unwrap();
        let s = h.summary();
        assert_eq!(s.failed, 1);
        assert_eq!(s.mismatches, vec!["a"]);
    }

    #[test]
    fn unrun_counted() {
        let mut h = PolicyTestHarness::new();
        h.add_case("a", "in", "allow").unwrap();
        let s = h.summary();
        assert_eq!(s.unrun, 1);
    }

    #[test]
    fn reset_clears() {
        let mut h = PolicyTestHarness::new();
        h.add_case("a", "in", "allow").unwrap();
        h.record_observed("a", "deny").unwrap();
        h.reset_observed();
        assert_eq!(h.summary().failed, 0);
    }

    #[test]
    fn duplicate_case_rejected() {
        let mut h = PolicyTestHarness::new();
        h.add_case("a", "in", "x").unwrap();
        assert!(matches!(h.add_case("a", "in", "x").unwrap_err(), HarnessError::DuplicateId(_)));
    }

    #[test]
    fn unknown_record_rejected() {
        let mut h = PolicyTestHarness::new();
        assert!(matches!(h.record_observed("nope", "x").unwrap_err(), HarnessError::UnknownCase(_)));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut h = PolicyTestHarness::new();
        assert!(matches!(h.add_case("", "in", "x").unwrap_err(), HarnessError::EmptyId));
        assert!(matches!(h.add_case("a", "in", "").unwrap_err(), HarnessError::EmptyExpected));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut h = PolicyTestHarness::new();
        h.schema_version = "9.9.9".into();
        assert!(matches!(h.validate().unwrap_err(), HarnessError::SchemaMismatch));
    }

    #[test]
    fn harness_serde_roundtrip() {
        let mut h = PolicyTestHarness::new();
        h.add_case("a", "in", "allow").unwrap();
        h.record_observed("a", "allow").unwrap();
        let j = serde_json::to_string(&h).unwrap();
        let back: PolicyTestHarness = serde_json::from_str(&j).unwrap();
        assert_eq!(h, back);
    }
}
