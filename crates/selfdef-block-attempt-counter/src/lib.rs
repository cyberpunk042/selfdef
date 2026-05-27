//! `selfdef-block-attempt-counter` — per-(actor, action) denial counter.
//!
//! `record(actor, action_kind, ts, blocked, reason)` updates the entry:
//! attempts++, blocks++ when blocked, last_attempt_ts, last_block_reason
//! when blocked. `stats(actor, action_kind)` returns the entry.
//!
//! Pure counter. Dashboard tiles read this for "actor X has been
//! blocked Y times on action Z this hour" panels.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-(actor, action_kind) stats.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Stats {
    /// Total attempts.
    pub attempts: u32,
    /// Total blocked.
    pub blocked: u32,
    /// Last attempt ts.
    pub last_attempt_ts_ms: u64,
    /// Last block reason.
    pub last_block_reason: Option<String>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockAttemptCounter {
    /// Schema version.
    pub schema_version: String,
    /// actor → action_kind → stats.
    pub buckets: BTreeMap<String, BTreeMap<String, Stats>>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CounterError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty actor.
    #[error("actor empty")]
    EmptyActor,
    /// Empty action kind.
    #[error("action kind empty")]
    EmptyKind,
    /// Non-monotonic.
    #[error("non-monotonic ts: prev {prev} > new {new}")]
    NonMonotonic {
        /// prev.
        prev: u64,
        /// new.
        new: u64,
    },
}

impl BlockAttemptCounter {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            buckets: BTreeMap::new(),
        }
    }

    /// Record an attempt.
    pub fn record(
        &mut self,
        actor: &str,
        action_kind: &str,
        ts_ms: u64,
        blocked: bool,
        reason: Option<&str>,
    ) -> Result<(), CounterError> {
        if actor.is_empty() {
            return Err(CounterError::EmptyActor);
        }
        if action_kind.is_empty() {
            return Err(CounterError::EmptyKind);
        }
        let by_kind = self.buckets.entry(actor.into()).or_default();
        let s = by_kind.entry(action_kind.into()).or_default();
        if ts_ms < s.last_attempt_ts_ms {
            return Err(CounterError::NonMonotonic {
                prev: s.last_attempt_ts_ms,
                new: ts_ms,
            });
        }
        s.attempts = s.attempts.saturating_add(1);
        if blocked {
            s.blocked = s.blocked.saturating_add(1);
            if let Some(r) = reason {
                s.last_block_reason = Some(r.into());
            }
        }
        s.last_attempt_ts_ms = ts_ms;
        Ok(())
    }

    /// Stats for (actor, kind).
    pub fn stats(&self, actor: &str, action_kind: &str) -> Option<Stats> {
        self.buckets.get(actor)?.get(action_kind).cloned()
    }

    /// Total blocked for an actor across all action kinds.
    pub fn blocked_total(&self, actor: &str) -> u32 {
        self.buckets
            .get(actor)
            .map(|by_kind| by_kind.values().map(|s| s.blocked).sum())
            .unwrap_or(0)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CounterError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CounterError::SchemaMismatch);
        }
        for a in self.buckets.keys() {
            if a.is_empty() {
                return Err(CounterError::EmptyActor);
            }
        }
        Ok(())
    }
}

impl Default for BlockAttemptCounter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_allowed() {
        let mut c = BlockAttemptCounter::new();
        c.record("actor", "read", 0, false, None).unwrap();
        let s = c.stats("actor", "read").unwrap();
        assert_eq!(s.attempts, 1);
        assert_eq!(s.blocked, 0);
    }

    #[test]
    fn record_blocked_with_reason() {
        let mut c = BlockAttemptCounter::new();
        c.record("actor", "write", 0, true, Some("no grant"))
            .unwrap();
        let s = c.stats("actor", "write").unwrap();
        assert_eq!(s.blocked, 1);
        assert_eq!(s.last_block_reason.as_deref(), Some("no grant"));
    }

    #[test]
    fn blocked_total_across_kinds() {
        let mut c = BlockAttemptCounter::new();
        c.record("actor", "read", 0, true, None).unwrap();
        c.record("actor", "write", 1, true, None).unwrap();
        c.record("actor", "write", 2, false, None).unwrap();
        assert_eq!(c.blocked_total("actor"), 2);
    }

    #[test]
    fn stats_unknown_returns_none() {
        let c = BlockAttemptCounter::new();
        assert!(c.stats("missing", "x").is_none());
    }

    #[test]
    fn nonmonotonic_rejected() {
        let mut c = BlockAttemptCounter::new();
        c.record("a", "k", 200, false, None).unwrap();
        assert!(matches!(
            c.record("a", "k", 100, false, None).unwrap_err(),
            CounterError::NonMonotonic { .. }
        ));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut c = BlockAttemptCounter::new();
        assert!(matches!(
            c.record("", "k", 0, false, None).unwrap_err(),
            CounterError::EmptyActor
        ));
        assert!(matches!(
            c.record("a", "", 0, false, None).unwrap_err(),
            CounterError::EmptyKind
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = BlockAttemptCounter::new();
        c.schema_version = "9.9.9".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            CounterError::SchemaMismatch
        ));
    }

    #[test]
    fn counter_serde_roundtrip() {
        let mut c = BlockAttemptCounter::new();
        c.record("a", "k", 0, true, Some("nope")).unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: BlockAttemptCounter = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
