//! `selfdef-action-precondition-checker` — declarative action gates.
//!
//! Each action carries a `Vec<Precondition>`. `evaluate(action_id,
//! ctx)` walks them and returns `Met` or `Unmet { missing: Vec<...> }`
//! with the exact preconditions that failed. Predicates are intent-
//! ful: `HasGrant`, `NotSuspended`, `WithinHours`, `EnvFlagPresent`,
//! `MinTrustScore`, `DepActionCompleted`.
//!
//! The context (`PreconditionCtx`) is the live snapshot caller passes
//! in; the checker is pure and does no I/O.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Precondition kinds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Precondition {
    /// Operator holds the named grant.
    HasGrant {
        /// grant id.
        grant_id: String,
    },
    /// Actor is not currently suspended.
    NotSuspended,
    /// Local clock falls inside [from_min, to_min] minutes-of-day.
    WithinHours {
        /// inclusive from (minutes since midnight).
        from_min: u16,
        /// exclusive to.
        to_min: u16,
    },
    /// Named env flag is present and truthy.
    EnvFlagPresent {
        /// name.
        name: String,
    },
    /// Trust score ≥ floor.
    MinTrustScore {
        /// floor 0..=1000.
        floor: u16,
    },
    /// A prerequisite action has completed.
    DepActionCompleted {
        /// dep action id.
        dep_action_id: String,
    },
}

/// Context snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreconditionCtx {
    /// Grants the operator currently holds.
    pub held_grants: BTreeSet<String>,
    /// Is the actor suspended?
    pub suspended: bool,
    /// Current minute-of-day.
    pub current_min: u16,
    /// Env flags present + truthy.
    pub env_flags: BTreeSet<String>,
    /// Current trust score 0..=1000.
    pub trust_score: u16,
    /// Completed dependency action ids.
    pub completed_actions: BTreeSet<String>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionPreconditionChecker {
    /// Schema version.
    pub schema_version: String,
    /// action_id → preconditions.
    pub map: BTreeMap<String, Vec<Precondition>>,
}

/// Verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CheckVerdict {
    /// All preconditions met.
    Met,
    /// One or more unmet.
    Unmet {
        /// Failing preconditions.
        missing: Vec<Precondition>,
    },
    /// Unknown action.
    UnknownAction,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CheckerError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty action id.
    #[error("action id empty")]
    EmptyId,
}

impl ActionPreconditionChecker {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            map: BTreeMap::new(),
        }
    }

    /// Set the preconditions for an action.
    pub fn set(&mut self, action_id: &str, preconditions: Vec<Precondition>) -> Result<(), CheckerError> {
        if action_id.is_empty() { return Err(CheckerError::EmptyId); }
        self.map.insert(action_id.into(), preconditions);
        Ok(())
    }

    /// Evaluate.
    pub fn evaluate(&self, action_id: &str, ctx: &PreconditionCtx) -> CheckVerdict {
        let preconditions = match self.map.get(action_id) {
            Some(p) => p,
            None => return CheckVerdict::UnknownAction,
        };
        let mut missing = Vec::new();
        for p in preconditions {
            if !Self::passes(p, ctx) { missing.push(p.clone()); }
        }
        if missing.is_empty() {
            CheckVerdict::Met
        } else {
            CheckVerdict::Unmet { missing }
        }
    }

    fn passes(p: &Precondition, ctx: &PreconditionCtx) -> bool {
        match p {
            Precondition::HasGrant { grant_id } => ctx.held_grants.contains(grant_id),
            Precondition::NotSuspended => !ctx.suspended,
            Precondition::WithinHours { from_min, to_min } => {
                if from_min <= to_min {
                    ctx.current_min >= *from_min && ctx.current_min < *to_min
                } else {
                    // wraps midnight.
                    ctx.current_min >= *from_min || ctx.current_min < *to_min
                }
            }
            Precondition::EnvFlagPresent { name } => ctx.env_flags.contains(name),
            Precondition::MinTrustScore { floor } => ctx.trust_score >= *floor,
            Precondition::DepActionCompleted { dep_action_id } => ctx.completed_actions.contains(dep_action_id),
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CheckerError> {
        if self.schema_version != SCHEMA_VERSION { return Err(CheckerError::SchemaMismatch); }
        for id in self.map.keys() {
            if id.is_empty() { return Err(CheckerError::EmptyId); }
        }
        Ok(())
    }
}

impl Default for ActionPreconditionChecker {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> PreconditionCtx { PreconditionCtx::default() }

    #[test]
    fn met_when_no_preconditions() {
        let mut c = ActionPreconditionChecker::new();
        c.set("a", vec![]).unwrap();
        assert_eq!(c.evaluate("a", &ctx()), CheckVerdict::Met);
    }

    #[test]
    fn unknown_action() {
        let c = ActionPreconditionChecker::new();
        assert_eq!(c.evaluate("nope", &ctx()), CheckVerdict::UnknownAction);
    }

    #[test]
    fn has_grant() {
        let mut c = ActionPreconditionChecker::new();
        c.set("a", vec![Precondition::HasGrant { grant_id: "g1".into() }]).unwrap();
        let mut ctx = ctx();
        assert!(matches!(c.evaluate("a", &ctx), CheckVerdict::Unmet { .. }));
        ctx.held_grants.insert("g1".into());
        assert_eq!(c.evaluate("a", &ctx), CheckVerdict::Met);
    }

    #[test]
    fn not_suspended() {
        let mut c = ActionPreconditionChecker::new();
        c.set("a", vec![Precondition::NotSuspended]).unwrap();
        let mut ctx = ctx();
        ctx.suspended = true;
        assert!(matches!(c.evaluate("a", &ctx), CheckVerdict::Unmet { .. }));
        ctx.suspended = false;
        assert_eq!(c.evaluate("a", &ctx), CheckVerdict::Met);
    }

    #[test]
    fn within_hours_normal() {
        let mut c = ActionPreconditionChecker::new();
        c.set("a", vec![Precondition::WithinHours { from_min: 9 * 60, to_min: 17 * 60 }]).unwrap();
        let mut ctx = ctx();
        ctx.current_min = 8 * 60;
        assert!(matches!(c.evaluate("a", &ctx), CheckVerdict::Unmet { .. }));
        ctx.current_min = 12 * 60;
        assert_eq!(c.evaluate("a", &ctx), CheckVerdict::Met);
    }

    #[test]
    fn within_hours_wraps_midnight() {
        let mut c = ActionPreconditionChecker::new();
        // 22:00..02:00 → wraps.
        c.set("a", vec![Precondition::WithinHours { from_min: 22 * 60, to_min: 2 * 60 }]).unwrap();
        let mut ctx = ctx();
        ctx.current_min = 23 * 60;
        assert_eq!(c.evaluate("a", &ctx), CheckVerdict::Met);
        ctx.current_min = 60;
        assert_eq!(c.evaluate("a", &ctx), CheckVerdict::Met);
        ctx.current_min = 12 * 60;
        assert!(matches!(c.evaluate("a", &ctx), CheckVerdict::Unmet { .. }));
    }

    #[test]
    fn env_flag() {
        let mut c = ActionPreconditionChecker::new();
        c.set("a", vec![Precondition::EnvFlagPresent { name: "X".into() }]).unwrap();
        let mut ctx = ctx();
        assert!(matches!(c.evaluate("a", &ctx), CheckVerdict::Unmet { .. }));
        ctx.env_flags.insert("X".into());
        assert_eq!(c.evaluate("a", &ctx), CheckVerdict::Met);
    }

    #[test]
    fn min_trust_score() {
        let mut c = ActionPreconditionChecker::new();
        c.set("a", vec![Precondition::MinTrustScore { floor: 500 }]).unwrap();
        let mut ctx = ctx();
        ctx.trust_score = 300;
        assert!(matches!(c.evaluate("a", &ctx), CheckVerdict::Unmet { .. }));
        ctx.trust_score = 800;
        assert_eq!(c.evaluate("a", &ctx), CheckVerdict::Met);
    }

    #[test]
    fn dep_action_completed() {
        let mut c = ActionPreconditionChecker::new();
        c.set("a", vec![Precondition::DepActionCompleted { dep_action_id: "init".into() }]).unwrap();
        let mut ctx = ctx();
        assert!(matches!(c.evaluate("a", &ctx), CheckVerdict::Unmet { .. }));
        ctx.completed_actions.insert("init".into());
        assert_eq!(c.evaluate("a", &ctx), CheckVerdict::Met);
    }

    #[test]
    fn multiple_unmet_reports_all() {
        let mut c = ActionPreconditionChecker::new();
        c.set("a", vec![
            Precondition::NotSuspended,
            Precondition::MinTrustScore { floor: 500 },
        ]).unwrap();
        let mut ctx = ctx();
        ctx.suspended = true;
        ctx.trust_score = 100;
        match c.evaluate("a", &ctx) {
            CheckVerdict::Unmet { missing } => assert_eq!(missing.len(), 2),
            _ => panic!("expected unmet with both"),
        }
    }

    #[test]
    fn empty_id_rejected() {
        let mut c = ActionPreconditionChecker::new();
        assert!(matches!(c.set("", vec![]).unwrap_err(), CheckerError::EmptyId));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = ActionPreconditionChecker::new();
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), CheckerError::SchemaMismatch));
    }

    #[test]
    fn checker_serde_roundtrip() {
        let mut c = ActionPreconditionChecker::new();
        c.set("a", vec![Precondition::NotSuspended]).unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: ActionPreconditionChecker = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
