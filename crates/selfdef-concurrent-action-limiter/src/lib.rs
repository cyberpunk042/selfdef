//! `selfdef-concurrent-action-limiter` — per-actor concurrency cap.
//!
//! `set_limit(actor, max)` records that actor's cap. `admit(actor,
//! action_id)` returns Admitted if in_flight < max, or Rejected{
//! in_flight, limit }. `release(action_id)` decrements; idempotent
//! per-action (releasing twice doesn't drop below 0). Different
//! actors are independent; an actor with no explicit limit gets a
//! default cap.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-actor state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorState {
    /// Max concurrent.
    pub limit: u32,
    /// In flight count.
    pub in_flight: u32,
    /// Total admitted.
    pub admitted_total: u64,
    /// Total rejected.
    pub rejected_total: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConcurrentActionLimiter {
    /// Schema version.
    pub schema_version: String,
    /// Default cap for un-configured actors.
    pub default_limit: u32,
    /// actor → state.
    pub actors: BTreeMap<String, ActorState>,
    /// action_id → owning actor (for releases).
    pub in_flight_actions: BTreeMap<String, String>,
}

/// Admit verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AdmitVerdict {
    /// Admitted.
    Admitted,
    /// Rejected — at limit.
    Rejected {
        /// in-flight at time of decision.
        in_flight: u32,
        /// the actor's limit.
        limit: u32,
    },
    /// Duplicate action id already in flight.
    Duplicate,
}

/// Errors.
#[derive(Debug, Error)]
pub enum LimiterError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty actor.
    #[error("actor empty")]
    EmptyActor,
    /// Empty action.
    #[error("action id empty")]
    EmptyAction,
}

impl ConcurrentActionLimiter {
    /// New with default cap.
    pub fn new(default_limit: u32) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            default_limit,
            actors: BTreeMap::new(),
            in_flight_actions: BTreeMap::new(),
        }
    }

    /// Set per-actor limit.
    pub fn set_limit(&mut self, actor: &str, max: u32) -> Result<(), LimiterError> {
        if actor.is_empty() {
            return Err(LimiterError::EmptyActor);
        }
        let s = self.actors.entry(actor.into()).or_insert(ActorState {
            limit: max,
            in_flight: 0,
            admitted_total: 0,
            rejected_total: 0,
        });
        s.limit = max;
        Ok(())
    }

    /// Try to admit.
    pub fn admit(&mut self, actor: &str, action_id: &str) -> Result<AdmitVerdict, LimiterError> {
        if actor.is_empty() {
            return Err(LimiterError::EmptyActor);
        }
        if action_id.is_empty() {
            return Err(LimiterError::EmptyAction);
        }
        if self.in_flight_actions.contains_key(action_id) {
            return Ok(AdmitVerdict::Duplicate);
        }
        let default = self.default_limit;
        let s = self.actors.entry(actor.into()).or_insert(ActorState {
            limit: default,
            in_flight: 0,
            admitted_total: 0,
            rejected_total: 0,
        });
        if s.in_flight >= s.limit {
            s.rejected_total = s.rejected_total.saturating_add(1);
            return Ok(AdmitVerdict::Rejected {
                in_flight: s.in_flight,
                limit: s.limit,
            });
        }
        s.in_flight = s.in_flight.saturating_add(1);
        s.admitted_total = s.admitted_total.saturating_add(1);
        self.in_flight_actions
            .insert(action_id.into(), actor.into());
        Ok(AdmitVerdict::Admitted)
    }

    /// Release. Returns true if the action was in flight.
    pub fn release(&mut self, action_id: &str) -> bool {
        let Some(actor) = self.in_flight_actions.remove(action_id) else {
            return false;
        };
        if let Some(s) = self.actors.get_mut(&actor) {
            s.in_flight = s.in_flight.saturating_sub(1);
        }
        true
    }

    /// Get in-flight count for an actor.
    pub fn in_flight(&self, actor: &str) -> u32 {
        self.actors.get(actor).map(|s| s.in_flight).unwrap_or(0)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), LimiterError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(LimiterError::SchemaMismatch);
        }
        for k in self.actors.keys() {
            if k.is_empty() {
                return Err(LimiterError::EmptyActor);
            }
        }
        for k in self.in_flight_actions.keys() {
            if k.is_empty() {
                return Err(LimiterError::EmptyAction);
            }
        }
        Ok(())
    }
}

impl Default for ConcurrentActionLimiter {
    fn default() -> Self {
        Self::new(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admit_under_limit() {
        let mut l = ConcurrentActionLimiter::new(2);
        assert_eq!(l.admit("alice", "a1").unwrap(), AdmitVerdict::Admitted);
        assert_eq!(l.admit("alice", "a2").unwrap(), AdmitVerdict::Admitted);
    }

    #[test]
    fn reject_at_limit() {
        let mut l = ConcurrentActionLimiter::new(1);
        assert_eq!(l.admit("alice", "a1").unwrap(), AdmitVerdict::Admitted);
        match l.admit("alice", "a2").unwrap() {
            AdmitVerdict::Rejected { in_flight, limit } => {
                assert_eq!(in_flight, 1);
                assert_eq!(limit, 1);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn release_frees_slot() {
        let mut l = ConcurrentActionLimiter::new(1);
        l.admit("alice", "a1").unwrap();
        assert!(l.release("a1"));
        assert_eq!(l.admit("alice", "a2").unwrap(), AdmitVerdict::Admitted);
    }

    #[test]
    fn duplicate_action_id() {
        let mut l = ConcurrentActionLimiter::new(5);
        l.admit("alice", "a1").unwrap();
        assert_eq!(l.admit("alice", "a1").unwrap(), AdmitVerdict::Duplicate);
        // Doesn't increment in_flight.
        assert_eq!(l.in_flight("alice"), 1);
    }

    #[test]
    fn release_unknown_false() {
        let mut l = ConcurrentActionLimiter::new(1);
        assert!(!l.release("nope"));
    }

    #[test]
    fn release_idempotent() {
        let mut l = ConcurrentActionLimiter::new(2);
        l.admit("alice", "a1").unwrap();
        assert!(l.release("a1"));
        assert!(!l.release("a1"));
    }

    #[test]
    fn different_actors_independent() {
        let mut l = ConcurrentActionLimiter::new(1);
        l.admit("alice", "a1").unwrap();
        // Bob hits his own limit, not alice's.
        assert_eq!(l.admit("bob", "b1").unwrap(), AdmitVerdict::Admitted);
    }

    #[test]
    fn set_limit_changes_cap() {
        let mut l = ConcurrentActionLimiter::new(1);
        l.admit("alice", "a1").unwrap();
        assert!(matches!(
            l.admit("alice", "a2").unwrap(),
            AdmitVerdict::Rejected { .. }
        ));
        l.set_limit("alice", 5).unwrap();
        assert_eq!(l.admit("alice", "a2").unwrap(), AdmitVerdict::Admitted);
    }

    #[test]
    fn counters_track() {
        let mut l = ConcurrentActionLimiter::new(1);
        l.admit("alice", "a1").unwrap();
        l.admit("alice", "a2").unwrap();
        let s = l.actors.get("alice").unwrap();
        assert_eq!(s.admitted_total, 1);
        assert_eq!(s.rejected_total, 1);
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut l = ConcurrentActionLimiter::new(1);
        assert!(matches!(
            l.admit("", "x").unwrap_err(),
            LimiterError::EmptyActor
        ));
        assert!(matches!(
            l.admit("a", "").unwrap_err(),
            LimiterError::EmptyAction
        ));
        assert!(matches!(
            l.set_limit("", 1).unwrap_err(),
            LimiterError::EmptyActor
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut l = ConcurrentActionLimiter::new(1);
        l.schema_version = "9.9.9".into();
        assert!(matches!(
            l.validate().unwrap_err(),
            LimiterError::SchemaMismatch
        ));
    }

    #[test]
    fn limiter_serde_roundtrip() {
        let mut l = ConcurrentActionLimiter::new(2);
        l.admit("alice", "a1").unwrap();
        let j = serde_json::to_string(&l).unwrap();
        let back: ConcurrentActionLimiter = serde_json::from_str(&j).unwrap();
        assert_eq!(l, back);
    }
}
