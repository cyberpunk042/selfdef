//! `selfdef-action-deadline-tracker` — per-action deadlines.
//!
//! `register(action_id, deadline_ms)` records when an action must
//! complete. `check(action_id, now_ms, warn_ms)` returns:
//!   * `OnTime { remaining_ms }` — well within deadline.
//!   * `Expiring { remaining_ms }` — within `warn_ms` of deadline.
//!   * `Expired { overdue_ms }` — past deadline.
//!   * `Unknown` — action not registered.
//!
//! `complete(action_id)` marks success (removes from tracking).
//! `extend(action_id, new_deadline_ms)` shifts the deadline (only
//! forward; never back). `expired(now_ms)` lists all overdue.
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
pub struct ActionDeadlineTracker {
    /// Schema version.
    pub schema_version: String,
    /// action_id → deadline_ms.
    pub deadlines: BTreeMap<String, u64>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DeadlineVerdict {
    /// On time.
    OnTime {
        /// remaining.
        remaining_ms: u64,
    },
    /// Within warn window.
    Expiring {
        /// remaining.
        remaining_ms: u64,
    },
    /// Past deadline.
    Expired {
        /// how overdue.
        overdue_ms: u64,
    },
    /// Unknown action.
    Unknown,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DeadlineError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty action id.
    #[error("action id empty")]
    EmptyAction,
    /// Unknown action.
    #[error("unknown action: {0}")]
    UnknownAction(String),
    /// Extend backward not allowed.
    #[error("extend backward not allowed: existing {existing} > new {new}")]
    BackwardExtend {
        /// existing.
        existing: u64,
        /// new.
        new: u64,
    },
}

impl ActionDeadlineTracker {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            deadlines: BTreeMap::new(),
        }
    }

    /// Register an action with a deadline.
    pub fn register(&mut self, action_id: &str, deadline_ms: u64) -> Result<(), DeadlineError> {
        if action_id.is_empty() {
            return Err(DeadlineError::EmptyAction);
        }
        self.deadlines.insert(action_id.into(), deadline_ms);
        Ok(())
    }

    /// Extend (forward-only).
    pub fn extend(&mut self, action_id: &str, new_deadline_ms: u64) -> Result<(), DeadlineError> {
        let existing = self
            .deadlines
            .get(action_id)
            .copied()
            .ok_or_else(|| DeadlineError::UnknownAction(action_id.into()))?;
        if new_deadline_ms < existing {
            return Err(DeadlineError::BackwardExtend {
                existing,
                new: new_deadline_ms,
            });
        }
        self.deadlines.insert(action_id.into(), new_deadline_ms);
        Ok(())
    }

    /// Check.
    pub fn check(&self, action_id: &str, now_ms: u64, warn_ms: u64) -> DeadlineVerdict {
        let Some(&deadline) = self.deadlines.get(action_id) else {
            return DeadlineVerdict::Unknown;
        };
        if now_ms >= deadline {
            return DeadlineVerdict::Expired {
                overdue_ms: now_ms - deadline,
            };
        }
        let remaining = deadline - now_ms;
        if remaining <= warn_ms {
            DeadlineVerdict::Expiring {
                remaining_ms: remaining,
            }
        } else {
            DeadlineVerdict::OnTime {
                remaining_ms: remaining,
            }
        }
    }

    /// Mark complete (drops tracking).
    pub fn complete(&mut self, action_id: &str) -> bool {
        self.deadlines.remove(action_id).is_some()
    }

    /// List currently-expired actions.
    pub fn expired(&self, now_ms: u64) -> Vec<String> {
        self.deadlines
            .iter()
            .filter(|&(_, &d)| now_ms >= d)
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DeadlineError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(DeadlineError::SchemaMismatch);
        }
        for k in self.deadlines.keys() {
            if k.is_empty() {
                return Err(DeadlineError::EmptyAction);
            }
        }
        Ok(())
    }
}

impl Default for ActionDeadlineTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ontime_far_from_deadline() {
        let mut t = ActionDeadlineTracker::new();
        t.register("a", 10_000).unwrap();
        assert!(matches!(
            t.check("a", 0, 1_000),
            DeadlineVerdict::OnTime {
                remaining_ms: 10_000
            }
        ));
    }

    #[test]
    fn expiring_in_warn_window() {
        let mut t = ActionDeadlineTracker::new();
        t.register("a", 10_000).unwrap();
        match t.check("a", 9_500, 1_000) {
            DeadlineVerdict::Expiring { remaining_ms } => assert_eq!(remaining_ms, 500),
            _ => panic!(),
        }
    }

    #[test]
    fn expired_past_deadline() {
        let mut t = ActionDeadlineTracker::new();
        t.register("a", 10_000).unwrap();
        match t.check("a", 12_000, 1_000) {
            DeadlineVerdict::Expired { overdue_ms } => assert_eq!(overdue_ms, 2_000),
            _ => panic!(),
        }
    }

    #[test]
    fn unknown_action_unknown_verdict() {
        let t = ActionDeadlineTracker::new();
        assert_eq!(t.check("nope", 0, 100), DeadlineVerdict::Unknown);
    }

    #[test]
    fn complete_drops_tracking() {
        let mut t = ActionDeadlineTracker::new();
        t.register("a", 10_000).unwrap();
        assert!(t.complete("a"));
        assert_eq!(t.check("a", 0, 1), DeadlineVerdict::Unknown);
    }

    #[test]
    fn extend_forward_ok() {
        let mut t = ActionDeadlineTracker::new();
        t.register("a", 10_000).unwrap();
        t.extend("a", 15_000).unwrap();
        assert_eq!(t.deadlines["a"], 15_000);
    }

    #[test]
    fn extend_backward_rejected() {
        let mut t = ActionDeadlineTracker::new();
        t.register("a", 10_000).unwrap();
        assert!(matches!(
            t.extend("a", 5_000).unwrap_err(),
            DeadlineError::BackwardExtend { .. }
        ));
    }

    #[test]
    fn extend_unknown_rejected() {
        let mut t = ActionDeadlineTracker::new();
        assert!(matches!(
            t.extend("nope", 10).unwrap_err(),
            DeadlineError::UnknownAction(_)
        ));
    }

    #[test]
    fn expired_lists_overdue() {
        let mut t = ActionDeadlineTracker::new();
        t.register("a", 100).unwrap();
        t.register("b", 10_000).unwrap();
        let e = t.expired(500);
        assert!(e.contains(&"a".to_string()));
        assert!(!e.contains(&"b".to_string()));
    }

    #[test]
    fn empty_action_rejected() {
        let mut t = ActionDeadlineTracker::new();
        assert!(matches!(
            t.register("", 1).unwrap_err(),
            DeadlineError::EmptyAction
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = ActionDeadlineTracker::new();
        t.schema_version = "9.9.9".into();
        assert!(matches!(
            t.validate().unwrap_err(),
            DeadlineError::SchemaMismatch
        ));
    }

    #[test]
    fn deadline_serde_roundtrip() {
        let mut t = ActionDeadlineTracker::new();
        t.register("a", 10_000).unwrap();
        let j = serde_json::to_string(&t).unwrap();
        let back: ActionDeadlineTracker = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
