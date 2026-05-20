//! `selfdef-action-step-budget` — sequential-step depth cap per action.
//!
//! Each Profile carries `max_steps`. `start(id, profile)` opens a
//! per-action counter; `step(id)` returns `Accepted{remaining}` or
//! `Exhausted{cap}`. `finish(id)` clears the counter.
//!
//! Distinct from the parallel-fanout budget — this is sequential
//! depth.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// Private.
    Private,
    /// Fast.
    Fast,
    /// Careful.
    Careful,
    /// Autonomous.
    Autonomous,
    /// Experimental.
    Experimental,
    /// Production.
    Production,
}

/// One in-flight action counter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counter {
    /// action id.
    pub id: String,
    /// profile.
    pub profile: Profile,
    /// steps taken so far.
    pub used: u32,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionStepBudget {
    /// Schema version.
    pub schema_version: String,
    /// Per-profile cap.
    pub max_steps: BTreeMap<Profile, u32>,
    /// In-flight counters.
    pub counters: Vec<Counter>,
}

/// Step verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum StepVerdict {
    /// Accepted.
    Accepted {
        /// remaining.
        remaining: u32,
    },
    /// Exhausted.
    Exhausted {
        /// cap.
        cap: u32,
    },
    /// Unknown action id.
    UnknownAction,
    /// Profile unconfigured.
    Unconfigured,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BudgetError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Duplicate.
    #[error("action {0} already started")]
    DuplicateAction(String),
    /// Unknown action.
    #[error("unknown action: {0}")]
    UnknownAction(String),
    /// Empty id.
    #[error("action id empty")]
    EmptyId,
}

impl ActionStepBudget {
    /// Canonical defaults.
    pub fn canonical() -> Self {
        let mut m = BTreeMap::new();
        m.insert(Profile::Private,      8);
        m.insert(Profile::Fast,         32);
        m.insert(Profile::Careful,      16);
        m.insert(Profile::Autonomous,   64);
        m.insert(Profile::Experimental, 256);
        m.insert(Profile::Production,   32);
        Self {
            schema_version: SCHEMA_VERSION.into(),
            max_steps: m,
            counters: Vec::new(),
        }
    }

    /// Start.
    pub fn start(&mut self, id: &str, profile: Profile) -> Result<(), BudgetError> {
        if id.is_empty() { return Err(BudgetError::EmptyId); }
        if self.counters.iter().any(|c| c.id == id) {
            return Err(BudgetError::DuplicateAction(id.into()));
        }
        self.counters.push(Counter { id: id.into(), profile, used: 0 });
        Ok(())
    }

    /// Step.
    pub fn step(&mut self, id: &str) -> StepVerdict {
        let pos = match self.counters.iter().position(|c| c.id == id) {
            Some(p) => p,
            None => return StepVerdict::UnknownAction,
        };
        let prof = self.counters[pos].profile;
        let cap = match self.max_steps.get(&prof) {
            Some(&c) => c,
            None => return StepVerdict::Unconfigured,
        };
        if self.counters[pos].used >= cap {
            return StepVerdict::Exhausted { cap };
        }
        self.counters[pos].used += 1;
        StepVerdict::Accepted { remaining: cap - self.counters[pos].used }
    }

    /// Finish.
    pub fn finish(&mut self, id: &str) -> Result<(), BudgetError> {
        let pos = self.counters.iter().position(|c| c.id == id)
            .ok_or_else(|| BudgetError::UnknownAction(id.into()))?;
        self.counters.remove(pos);
        Ok(())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BudgetError> {
        if self.schema_version != SCHEMA_VERSION { return Err(BudgetError::SchemaMismatch); }
        for c in &self.counters {
            if c.id.is_empty() { return Err(BudgetError::EmptyId); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        ActionStepBudget::canonical().validate().unwrap();
    }

    #[test]
    fn step_accepts_then_exhausts() {
        let mut b = ActionStepBudget::canonical();
        b.max_steps.insert(Profile::Fast, 3);
        b.start("a", Profile::Fast).unwrap();
        assert_eq!(b.step("a"), StepVerdict::Accepted { remaining: 2 });
        assert_eq!(b.step("a"), StepVerdict::Accepted { remaining: 1 });
        assert_eq!(b.step("a"), StepVerdict::Accepted { remaining: 0 });
        assert_eq!(b.step("a"), StepVerdict::Exhausted { cap: 3 });
    }

    #[test]
    fn unknown_action_step() {
        let mut b = ActionStepBudget::canonical();
        assert_eq!(b.step("nope"), StepVerdict::UnknownAction);
    }

    #[test]
    fn unconfigured_profile() {
        let mut b = ActionStepBudget::canonical();
        b.start("a", Profile::Fast).unwrap();
        b.max_steps.clear();
        assert_eq!(b.step("a"), StepVerdict::Unconfigured);
    }

    #[test]
    fn duplicate_start_rejected() {
        let mut b = ActionStepBudget::canonical();
        b.start("a", Profile::Fast).unwrap();
        assert!(matches!(b.start("a", Profile::Fast).unwrap_err(), BudgetError::DuplicateAction(_)));
    }

    #[test]
    fn empty_id_rejected() {
        let mut b = ActionStepBudget::canonical();
        assert!(matches!(b.start("", Profile::Fast).unwrap_err(), BudgetError::EmptyId));
    }

    #[test]
    fn finish_clears() {
        let mut b = ActionStepBudget::canonical();
        b.start("a", Profile::Fast).unwrap();
        b.finish("a").unwrap();
        assert!(matches!(b.finish("a").unwrap_err(), BudgetError::UnknownAction(_)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut b = ActionStepBudget::canonical();
        b.schema_version = "9.9.9".into();
        assert!(matches!(b.validate().unwrap_err(), BudgetError::SchemaMismatch));
    }

    #[test]
    fn budget_serde_roundtrip() {
        let mut b = ActionStepBudget::canonical();
        b.start("a", Profile::Fast).unwrap();
        b.step("a");
        let j = serde_json::to_string(&b).unwrap();
        let back: ActionStepBudget = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
