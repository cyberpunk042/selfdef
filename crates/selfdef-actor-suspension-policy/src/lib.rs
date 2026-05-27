//! `selfdef-actor-suspension-policy` — per-actor suspension w/ auto-thaw.
//!
//! `suspend(actor, reason, unsuspend_at)` records a moratorium.
//! `classify(actor, now)` returns:
//!   * `Active` — no record, or `now ≥ unsuspend_at`.
//!   * `Suspended { reason, unsuspend_at_ms }` — still in the window.
//!   * `Unknown` — no record for this actor.
//!
//! `unsuspend(actor)` clears immediately. Records auto-thaw via
//! `classify`; `rotate(now)` evicts expired records.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One suspension entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Suspension {
    /// reason label.
    pub reason: String,
    /// auto-thaw ts.
    pub unsuspend_at_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorSuspensionPolicy {
    /// Schema version.
    pub schema_version: String,
    /// actor → suspension.
    pub records: BTreeMap<String, Suspension>,
}

/// Verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SuspensionVerdict {
    /// Active — no record or thawed.
    Active,
    /// Suspended in window.
    Suspended {
        /// reason.
        reason: String,
        /// unsuspend_at_ms.
        unsuspend_at_ms: u64,
    },
    /// Unknown actor (never seen).
    Unknown,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SuspensionError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty actor.
    #[error("actor empty")]
    EmptyActor,
    /// Empty reason.
    #[error("reason empty")]
    EmptyReason,
}

impl ActorSuspensionPolicy {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            records: BTreeMap::new(),
        }
    }

    /// Suspend.
    pub fn suspend(
        &mut self,
        actor: &str,
        reason: &str,
        unsuspend_at_ms: u64,
    ) -> Result<(), SuspensionError> {
        if actor.is_empty() {
            return Err(SuspensionError::EmptyActor);
        }
        if reason.is_empty() {
            return Err(SuspensionError::EmptyReason);
        }
        self.records.insert(
            actor.into(),
            Suspension {
                reason: reason.into(),
                unsuspend_at_ms,
            },
        );
        Ok(())
    }

    /// Unsuspend immediately.
    pub fn unsuspend(&mut self, actor: &str) -> bool {
        self.records.remove(actor).is_some()
    }

    /// Classify.
    pub fn classify(&self, actor: &str, now_ms: u64) -> SuspensionVerdict {
        match self.records.get(actor) {
            None => SuspensionVerdict::Unknown,
            Some(s) => {
                if now_ms >= s.unsuspend_at_ms {
                    SuspensionVerdict::Active
                } else {
                    SuspensionVerdict::Suspended {
                        reason: s.reason.clone(),
                        unsuspend_at_ms: s.unsuspend_at_ms,
                    }
                }
            }
        }
    }

    /// Rotate — drop expired records.
    pub fn rotate(&mut self, now_ms: u64) {
        self.records.retain(|_, s| now_ms < s.unsuspend_at_ms);
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), SuspensionError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SuspensionError::SchemaMismatch);
        }
        for (k, v) in &self.records {
            if k.is_empty() {
                return Err(SuspensionError::EmptyActor);
            }
            if v.reason.is_empty() {
                return Err(SuspensionError::EmptyReason);
            }
        }
        Ok(())
    }
}

impl Default for ActorSuspensionPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_actor() {
        let p = ActorSuspensionPolicy::new();
        assert_eq!(p.classify("a", 0), SuspensionVerdict::Unknown);
    }

    #[test]
    fn suspended_in_window() {
        let mut p = ActorSuspensionPolicy::new();
        p.suspend("a", "spam", 1000).unwrap();
        let v = p.classify("a", 500);
        match v {
            SuspensionVerdict::Suspended {
                reason,
                unsuspend_at_ms,
            } => {
                assert_eq!(reason, "spam");
                assert_eq!(unsuspend_at_ms, 1000);
            }
            _ => panic!("expected suspended"),
        }
    }

    #[test]
    fn auto_thaw_at_or_past() {
        let mut p = ActorSuspensionPolicy::new();
        p.suspend("a", "spam", 1000).unwrap();
        assert_eq!(p.classify("a", 1000), SuspensionVerdict::Active);
        assert_eq!(p.classify("a", 2000), SuspensionVerdict::Active);
    }

    #[test]
    fn unsuspend_clears() {
        let mut p = ActorSuspensionPolicy::new();
        p.suspend("a", "spam", 10_000).unwrap();
        assert!(p.unsuspend("a"));
        assert_eq!(p.classify("a", 0), SuspensionVerdict::Unknown);
    }

    #[test]
    fn unsuspend_unknown_false() {
        let mut p = ActorSuspensionPolicy::new();
        assert!(!p.unsuspend("a"));
    }

    #[test]
    fn empty_actor_rejected() {
        let mut p = ActorSuspensionPolicy::new();
        assert!(matches!(
            p.suspend("", "x", 1).unwrap_err(),
            SuspensionError::EmptyActor
        ));
    }

    #[test]
    fn empty_reason_rejected() {
        let mut p = ActorSuspensionPolicy::new();
        assert!(matches!(
            p.suspend("a", "", 1).unwrap_err(),
            SuspensionError::EmptyReason
        ));
    }

    #[test]
    fn rotate_evicts_expired() {
        let mut p = ActorSuspensionPolicy::new();
        p.suspend("a", "x", 100).unwrap();
        p.suspend("b", "x", 10_000).unwrap();
        p.rotate(500);
        assert!(!p.records.contains_key("a"));
        assert!(p.records.contains_key("b"));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = ActorSuspensionPolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            SuspensionError::SchemaMismatch
        ));
    }

    #[test]
    fn suspension_serde_roundtrip() {
        let mut p = ActorSuspensionPolicy::new();
        p.suspend("a", "spam", 1000).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: ActorSuspensionPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
