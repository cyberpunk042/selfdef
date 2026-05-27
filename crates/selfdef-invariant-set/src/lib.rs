//! `selfdef-invariant-set` — named-invariant violation tracker.
//!
//! register(name) creates an Invariant{name, holds: true,
//! violations: 0}. report(name, holds) records the latest
//! state; holds=false bumps violations counter. failing()
//! lists invariants whose latest holds=false.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Invariant record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Invariant {
    /// Most recent holds state.
    pub holds: bool,
    /// Violations counter.
    pub violations: u64,
    /// Last report ts ms (0 = never).
    pub last_ts_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvariantSet {
    /// Schema version.
    pub schema_version: String,
    /// name → invariant.
    pub invariants: BTreeMap<String, Invariant>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum InvariantError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("name empty")]
    EmptyName,
    /// Duplicate.
    #[error("duplicate invariant: {0}")]
    DuplicateInvariant(String),
    /// Unknown.
    #[error("unknown invariant: {0}")]
    UnknownInvariant(String),
}

impl InvariantSet {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            invariants: BTreeMap::new(),
        }
    }

    /// Register an invariant (initial holds=true).
    pub fn register(&mut self, name: &str) -> Result<(), InvariantError> {
        if name.is_empty() {
            return Err(InvariantError::EmptyName);
        }
        if self.invariants.contains_key(name) {
            return Err(InvariantError::DuplicateInvariant(name.into()));
        }
        self.invariants.insert(
            name.into(),
            Invariant {
                holds: true,
                violations: 0,
                last_ts_ms: 0,
            },
        );
        Ok(())
    }

    /// Report latest state.
    pub fn report(&mut self, name: &str, holds: bool, ts_ms: u64) -> Result<(), InvariantError> {
        let inv = self
            .invariants
            .get_mut(name)
            .ok_or_else(|| InvariantError::UnknownInvariant(name.into()))?;
        inv.holds = holds;
        inv.last_ts_ms = ts_ms;
        if !holds {
            inv.violations = inv.violations.saturating_add(1);
        }
        Ok(())
    }

    /// Currently-failing invariants (latest holds=false).
    pub fn failing(&self) -> Vec<&str> {
        self.invariants
            .iter()
            .filter(|(_, v)| !v.holds)
            .map(|(k, _)| k.as_str())
            .collect()
    }

    /// All holding?
    pub fn all_holding(&self) -> bool {
        self.invariants.values().all(|v| v.holds)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), InvariantError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(InvariantError::SchemaMismatch);
        }
        for k in self.invariants.keys() {
            if k.is_empty() {
                return Err(InvariantError::EmptyName);
            }
        }
        Ok(())
    }
}

impl Default for InvariantSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_holding() {
        let mut s = InvariantSet::new();
        s.register("safe").unwrap();
        assert!(s.all_holding());
    }

    #[test]
    fn report_violation() {
        let mut s = InvariantSet::new();
        s.register("safe").unwrap();
        s.report("safe", false, 100).unwrap();
        assert!(!s.all_holding());
        assert_eq!(s.failing(), vec!["safe"]);
        assert_eq!(s.invariants.get("safe").unwrap().violations, 1);
    }

    #[test]
    fn report_recovery() {
        let mut s = InvariantSet::new();
        s.register("safe").unwrap();
        s.report("safe", false, 100).unwrap();
        s.report("safe", true, 200).unwrap();
        assert!(s.all_holding());
        // Violations remain at 1.
        assert_eq!(s.invariants.get("safe").unwrap().violations, 1);
    }

    #[test]
    fn duplicate_register_rejected() {
        let mut s = InvariantSet::new();
        s.register("a").unwrap();
        assert!(matches!(
            s.register("a").unwrap_err(),
            InvariantError::DuplicateInvariant(_)
        ));
    }

    #[test]
    fn unknown_report_rejected() {
        let mut s = InvariantSet::new();
        assert!(matches!(
            s.report("nope", true, 0).unwrap_err(),
            InvariantError::UnknownInvariant(_)
        ));
    }

    #[test]
    fn empty_name_rejected() {
        let mut s = InvariantSet::new();
        assert!(matches!(
            s.register("").unwrap_err(),
            InvariantError::EmptyName
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = InvariantSet::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            InvariantError::SchemaMismatch
        ));
    }

    #[test]
    fn set_serde_roundtrip() {
        let mut s = InvariantSet::new();
        s.register("safe").unwrap();
        s.report("safe", true, 100).unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: InvariantSet = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
