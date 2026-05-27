//! `selfdef-action-lifecycle` — action state machine.
//!
//! `Requested → Approved → Executing → Completed | Failed | Cancelled`.
//! Bad transitions are rejected. Each phase entry records its ts.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    /// Requested by actor.
    Requested,
    /// Approved by gates.
    Approved,
    /// Executing.
    Executing,
    /// Completed successfully.
    Completed,
    /// Failed.
    Failed,
    /// Cancelled.
    Cancelled,
}

/// One action's record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionRecord {
    /// Current phase.
    pub phase: Phase,
    /// (Phase → ts ms) history.
    pub history: BTreeMap<String, u64>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionLifecycle {
    /// Schema version.
    pub schema_version: String,
    /// action_id → record.
    pub actions: BTreeMap<String, ActionRecord>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum LifecycleError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty action id.
    #[error("action id empty")]
    EmptyId,
    /// Duplicate.
    #[error("duplicate action: {0}")]
    Duplicate(String),
    /// Unknown.
    #[error("unknown action: {0}")]
    Unknown(String),
    /// Bad transition.
    #[error("bad transition {from:?} → {to:?}")]
    BadTransition {
        /// from.
        from: Phase,
        /// to.
        to: Phase,
    },
}

fn allowed(from: Phase, to: Phase) -> bool {
    matches!(
        (from, to),
        (Phase::Requested, Phase::Approved)
            | (Phase::Requested, Phase::Cancelled)
            | (Phase::Approved, Phase::Executing)
            | (Phase::Approved, Phase::Cancelled)
            | (Phase::Executing, Phase::Completed)
            | (Phase::Executing, Phase::Failed)
            | (Phase::Executing, Phase::Cancelled)
    )
}

fn phase_key(p: Phase) -> &'static str {
    match p {
        Phase::Requested => "requested",
        Phase::Approved => "approved",
        Phase::Executing => "executing",
        Phase::Completed => "completed",
        Phase::Failed => "failed",
        Phase::Cancelled => "cancelled",
    }
}

impl ActionLifecycle {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            actions: BTreeMap::new(),
        }
    }

    /// Request an action (entry point).
    pub fn request(&mut self, action_id: &str, ts_ms: u64) -> Result<(), LifecycleError> {
        if action_id.is_empty() {
            return Err(LifecycleError::EmptyId);
        }
        if self.actions.contains_key(action_id) {
            return Err(LifecycleError::Duplicate(action_id.into()));
        }
        let mut history = BTreeMap::new();
        history.insert(phase_key(Phase::Requested).into(), ts_ms);
        self.actions.insert(
            action_id.into(),
            ActionRecord {
                phase: Phase::Requested,
                history,
            },
        );
        Ok(())
    }

    /// Advance.
    pub fn advance(
        &mut self,
        action_id: &str,
        to: Phase,
        ts_ms: u64,
    ) -> Result<(), LifecycleError> {
        let rec = self
            .actions
            .get_mut(action_id)
            .ok_or_else(|| LifecycleError::Unknown(action_id.into()))?;
        if !allowed(rec.phase, to) {
            return Err(LifecycleError::BadTransition {
                from: rec.phase,
                to,
            });
        }
        rec.phase = to;
        rec.history.insert(phase_key(to).into(), ts_ms);
        Ok(())
    }

    /// Current phase.
    pub fn phase_of(&self, action_id: &str) -> Option<Phase> {
        self.actions.get(action_id).map(|r| r.phase)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), LifecycleError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(LifecycleError::SchemaMismatch);
        }
        for id in self.actions.keys() {
            if id.is_empty() {
                return Err(LifecycleError::EmptyId);
            }
        }
        Ok(())
    }
}

impl Default for ActionLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_happy_path() {
        let mut l = ActionLifecycle::new();
        l.request("a", 0).unwrap();
        l.advance("a", Phase::Approved, 100).unwrap();
        l.advance("a", Phase::Executing, 200).unwrap();
        l.advance("a", Phase::Completed, 300).unwrap();
        assert_eq!(l.phase_of("a"), Some(Phase::Completed));
    }

    #[test]
    fn cancel_from_requested() {
        let mut l = ActionLifecycle::new();
        l.request("a", 0).unwrap();
        l.advance("a", Phase::Cancelled, 100).unwrap();
        assert_eq!(l.phase_of("a"), Some(Phase::Cancelled));
    }

    #[test]
    fn fail_from_executing() {
        let mut l = ActionLifecycle::new();
        l.request("a", 0).unwrap();
        l.advance("a", Phase::Approved, 100).unwrap();
        l.advance("a", Phase::Executing, 200).unwrap();
        l.advance("a", Phase::Failed, 300).unwrap();
        assert_eq!(l.phase_of("a"), Some(Phase::Failed));
    }

    #[test]
    fn bad_transition_rejected() {
        let mut l = ActionLifecycle::new();
        l.request("a", 0).unwrap();
        // Requested → Executing not allowed.
        assert!(matches!(
            l.advance("a", Phase::Executing, 100).unwrap_err(),
            LifecycleError::BadTransition { .. }
        ));
    }

    #[test]
    fn duplicate_request_rejected() {
        let mut l = ActionLifecycle::new();
        l.request("a", 0).unwrap();
        assert!(matches!(
            l.request("a", 100).unwrap_err(),
            LifecycleError::Duplicate(_)
        ));
    }

    #[test]
    fn empty_id_rejected() {
        let mut l = ActionLifecycle::new();
        assert!(matches!(
            l.request("", 0).unwrap_err(),
            LifecycleError::EmptyId
        ));
    }

    #[test]
    fn unknown_advance_rejected() {
        let mut l = ActionLifecycle::new();
        assert!(matches!(
            l.advance("a", Phase::Approved, 0).unwrap_err(),
            LifecycleError::Unknown(_)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut l = ActionLifecycle::new();
        l.schema_version = "9.9.9".into();
        assert!(matches!(
            l.validate().unwrap_err(),
            LifecycleError::SchemaMismatch
        ));
    }

    #[test]
    fn lifecycle_serde_roundtrip() {
        let mut l = ActionLifecycle::new();
        l.request("a", 0).unwrap();
        let j = serde_json::to_string(&l).unwrap();
        let back: ActionLifecycle = serde_json::from_str(&j).unwrap();
        assert_eq!(l, back);
    }
}
