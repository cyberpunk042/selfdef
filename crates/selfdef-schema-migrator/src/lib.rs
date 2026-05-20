//! `selfdef-schema-migrator` — semver-style schema versions.
//!
//! Schemas form a linear chain `v1 → v2 → v3 …`. Each `Step` is
//! `{ from, to, label }`. `plan(from, to)` returns the ordered list
//! of step labels to apply (forward or in reverse with "rollback:"
//! prefix). The registry stores migrations indexed by `(from, to)`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One migration step.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Step {
    /// From version.
    pub from: u32,
    /// To version (always from + 1).
    pub to: u32,
    /// Human label.
    pub label: String,
    /// Reversible?
    pub reversible: bool,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaMigrator {
    /// Schema version.
    pub schema_version: String,
    /// from → step (from + 1 is implicit).
    pub steps: BTreeMap<u32, Step>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum MigratorError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("label empty")]
    EmptyLabel,
    /// Non-consecutive.
    #[error("step must be from→from+1, got {from}→{to}")]
    NonConsecutive {
        /// from.
        from: u32,
        /// to.
        to: u32,
    },
    /// Duplicate.
    #[error("step from {0} already registered")]
    Duplicate(u32),
    /// Missing.
    #[error("missing step at from {0}")]
    Missing(u32),
    /// Non-reversible.
    #[error("step from {from}→{to} is not reversible")]
    NotReversible {
        /// from.
        from: u32,
        /// to.
        to: u32,
    },
}

impl SchemaMigrator {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            steps: BTreeMap::new(),
        }
    }

    /// Register.
    pub fn register(&mut self, step: Step) -> Result<(), MigratorError> {
        if step.label.is_empty() { return Err(MigratorError::EmptyLabel); }
        if step.to != step.from.saturating_add(1) {
            return Err(MigratorError::NonConsecutive { from: step.from, to: step.to });
        }
        if self.steps.contains_key(&step.from) {
            return Err(MigratorError::Duplicate(step.from));
        }
        self.steps.insert(step.from, step);
        Ok(())
    }

    /// Plan (forward or backward).
    pub fn plan(&self, from: u32, to: u32) -> Result<Vec<String>, MigratorError> {
        if from == to { return Ok(Vec::new()); }
        let mut out = Vec::new();
        if from < to {
            let mut cur = from;
            while cur < to {
                let step = self.steps.get(&cur).ok_or(MigratorError::Missing(cur))?;
                out.push(step.label.clone());
                cur = cur.saturating_add(1);
            }
        } else {
            // Backward: walk from (from-1) down to to.
            let mut cur = from;
            while cur > to {
                let prev = cur.saturating_sub(1);
                let step = self.steps.get(&prev).ok_or(MigratorError::Missing(prev))?;
                if !step.reversible {
                    return Err(MigratorError::NotReversible { from: step.from, to: step.to });
                }
                out.push(format!("rollback:{}", step.label));
                cur = prev;
            }
        }
        Ok(out)
    }

    /// Highest registered version (max to).
    pub fn highest(&self) -> u32 {
        self.steps.values().map(|s| s.to).max().unwrap_or(0)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), MigratorError> {
        if self.schema_version != SCHEMA_VERSION { return Err(MigratorError::SchemaMismatch); }
        for (k, s) in &self.steps {
            if *k != s.from { return Err(MigratorError::NonConsecutive { from: *k, to: s.from }); }
            if s.to != s.from.saturating_add(1) {
                return Err(MigratorError::NonConsecutive { from: s.from, to: s.to });
            }
            if s.label.is_empty() { return Err(MigratorError::EmptyLabel); }
        }
        Ok(())
    }
}

impl Default for SchemaMigrator {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(from: u32, label: &str, reversible: bool) -> Step {
        Step { from, to: from + 1, label: label.into(), reversible }
    }

    #[test]
    fn forward_plan() {
        let mut m = SchemaMigrator::new();
        m.register(step(1, "add table x", true)).unwrap();
        m.register(step(2, "add column y", true)).unwrap();
        let p = m.plan(1, 3).unwrap();
        assert_eq!(p, vec!["add table x", "add column y"]);
    }

    #[test]
    fn backward_plan_rollback_prefix() {
        let mut m = SchemaMigrator::new();
        m.register(step(1, "add x", true)).unwrap();
        m.register(step(2, "add y", true)).unwrap();
        let p = m.plan(3, 1).unwrap();
        assert_eq!(p, vec!["rollback:add y", "rollback:add x"]);
    }

    #[test]
    fn non_reversible_blocks_backward() {
        let mut m = SchemaMigrator::new();
        m.register(step(1, "destroy data", false)).unwrap();
        assert!(matches!(m.plan(2, 1).unwrap_err(), MigratorError::NotReversible { .. }));
    }

    #[test]
    fn missing_step_rejected() {
        let mut m = SchemaMigrator::new();
        m.register(step(1, "x", true)).unwrap();
        // No step from 2.
        assert!(matches!(m.plan(1, 3).unwrap_err(), MigratorError::Missing(2)));
    }

    #[test]
    fn no_op_same_version() {
        let m = SchemaMigrator::new();
        assert!(m.plan(5, 5).unwrap().is_empty());
    }

    #[test]
    fn non_consecutive_rejected() {
        let mut m = SchemaMigrator::new();
        let bad = Step { from: 1, to: 3, label: "x".into(), reversible: true };
        assert!(matches!(m.register(bad).unwrap_err(), MigratorError::NonConsecutive { .. }));
    }

    #[test]
    fn duplicate_rejected() {
        let mut m = SchemaMigrator::new();
        m.register(step(1, "x", true)).unwrap();
        assert!(matches!(m.register(step(1, "y", true)).unwrap_err(), MigratorError::Duplicate(1)));
    }

    #[test]
    fn empty_label_rejected() {
        let mut m = SchemaMigrator::new();
        assert!(matches!(m.register(step(1, "", true)).unwrap_err(), MigratorError::EmptyLabel));
    }

    #[test]
    fn highest_tracks_max() {
        let mut m = SchemaMigrator::new();
        m.register(step(1, "a", true)).unwrap();
        m.register(step(2, "b", true)).unwrap();
        assert_eq!(m.highest(), 3);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut m = SchemaMigrator::new();
        m.schema_version = "9.9.9".into();
        assert!(matches!(m.validate().unwrap_err(), MigratorError::SchemaMismatch));
    }

    #[test]
    fn migrator_serde_roundtrip() {
        let mut m = SchemaMigrator::new();
        m.register(step(1, "x", true)).unwrap();
        let j = serde_json::to_string(&m).unwrap();
        let back: SchemaMigrator = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
    }
}
