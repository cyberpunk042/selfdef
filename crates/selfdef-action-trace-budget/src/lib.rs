//! `selfdef-action-trace-budget` — per-action span cap.
//!
//! Each `action_id` is opened with `max_spans`. `admit(id)` returns:
//!   * `Accepted{used}` — under cap, span counted.
//!   * `Exhausted{cap}` — over cap, no further spans counted.
//!   * `UnknownAction` — id not opened.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-action counter.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counter {
    /// Cap.
    pub max_spans: u32,
    /// Used so far.
    pub used: u32,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionTraceBudget {
    /// Schema version.
    pub schema_version: String,
    /// action_id → counter.
    pub counters: BTreeMap<String, Counter>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SpanVerdict {
    /// Accepted.
    Accepted {
        /// used count after.
        used: u32,
    },
    /// Exhausted.
    Exhausted {
        /// cap.
        cap: u32,
    },
    /// Unknown action.
    UnknownAction,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BudgetError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("action id empty")]
    EmptyId,
    /// Duplicate.
    #[error("duplicate action: {0}")]
    Duplicate(String),
    /// Unknown.
    #[error("unknown action: {0}")]
    Unknown(String),
}

impl ActionTraceBudget {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            counters: BTreeMap::new(),
        }
    }

    /// Start.
    pub fn start(&mut self, action_id: &str, max_spans: u32) -> Result<(), BudgetError> {
        if action_id.is_empty() {
            return Err(BudgetError::EmptyId);
        }
        if self.counters.contains_key(action_id) {
            return Err(BudgetError::Duplicate(action_id.into()));
        }
        self.counters
            .insert(action_id.into(), Counter { max_spans, used: 0 });
        Ok(())
    }

    /// Admit.
    pub fn admit(&mut self, action_id: &str) -> SpanVerdict {
        let c = match self.counters.get_mut(action_id) {
            Some(c) => c,
            None => return SpanVerdict::UnknownAction,
        };
        if c.used >= c.max_spans {
            return SpanVerdict::Exhausted { cap: c.max_spans };
        }
        c.used = c.used.saturating_add(1);
        SpanVerdict::Accepted { used: c.used }
    }

    /// Finish.
    pub fn finish(&mut self, action_id: &str) -> Result<(), BudgetError> {
        self.counters
            .remove(action_id)
            .ok_or_else(|| BudgetError::Unknown(action_id.into()))?;
        Ok(())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BudgetError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BudgetError::SchemaMismatch);
        }
        for k in self.counters.keys() {
            if k.is_empty() {
                return Err(BudgetError::EmptyId);
            }
        }
        Ok(())
    }
}

impl Default for ActionTraceBudget {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_when_not_started() {
        let mut b = ActionTraceBudget::new();
        assert_eq!(b.admit("x"), SpanVerdict::UnknownAction);
    }

    #[test]
    fn admit_then_exhaust() {
        let mut b = ActionTraceBudget::new();
        b.start("x", 2).unwrap();
        assert_eq!(b.admit("x"), SpanVerdict::Accepted { used: 1 });
        assert_eq!(b.admit("x"), SpanVerdict::Accepted { used: 2 });
        assert_eq!(b.admit("x"), SpanVerdict::Exhausted { cap: 2 });
    }

    #[test]
    fn duplicate_start_rejected() {
        let mut b = ActionTraceBudget::new();
        b.start("x", 1).unwrap();
        assert!(matches!(
            b.start("x", 1).unwrap_err(),
            BudgetError::Duplicate(_)
        ));
    }

    #[test]
    fn finish_unknown_rejected() {
        let mut b = ActionTraceBudget::new();
        assert!(matches!(
            b.finish("x").unwrap_err(),
            BudgetError::Unknown(_)
        ));
    }

    #[test]
    fn finish_clears() {
        let mut b = ActionTraceBudget::new();
        b.start("x", 2).unwrap();
        b.finish("x").unwrap();
        assert_eq!(b.admit("x"), SpanVerdict::UnknownAction);
    }

    #[test]
    fn empty_id_rejected() {
        let mut b = ActionTraceBudget::new();
        assert!(matches!(b.start("", 1).unwrap_err(), BudgetError::EmptyId));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut b = ActionTraceBudget::new();
        b.schema_version = "9.9.9".into();
        assert!(matches!(
            b.validate().unwrap_err(),
            BudgetError::SchemaMismatch
        ));
    }

    #[test]
    fn budget_serde_roundtrip() {
        let mut b = ActionTraceBudget::new();
        b.start("x", 2).unwrap();
        b.admit("x");
        let j = serde_json::to_string(&b).unwrap();
        let back: ActionTraceBudget = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
