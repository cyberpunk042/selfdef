//! `selfdef-action-idempotency-key` — at-least-once retry-safe ledger.
//!
//! Operators / clients submit actions with an `idempotency_key`. The
//! ledger ensures:
//!
//!   * First submission for a key returns `Fresh { recorded_at_ms }`
//!     and is recorded.
//!   * Subsequent submissions return `Replay { first_seen_ts_ms,
//!     recorded_outcome }` — outcome is `None` until `complete()`
//!     attaches it.
//!
//! `rotate(now)` evicts entries older than retention.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Recorded outcome (free-form opaque string from caller).
pub type Outcome = String;

/// Ledger entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// First-seen ts.
    pub first_seen_ts_ms: u64,
    /// Outcome once known.
    pub outcome: Option<Outcome>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionIdempotencyKey {
    /// Schema version.
    pub schema_version: String,
    /// Retention (ms).
    pub retention_ms: u64,
    /// key → entry.
    pub ledger: BTreeMap<String, Entry>,
}

/// Submit verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SubmitVerdict {
    /// First time.
    Fresh {
        /// when recorded.
        recorded_at_ms: u64,
    },
    /// Replay.
    Replay {
        /// when first recorded.
        first_seen_ts_ms: u64,
        /// outcome if known.
        recorded_outcome: Option<Outcome>,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum LedgerError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty key.
    #[error("idempotency key empty")]
    EmptyKey,
    /// Unknown key.
    #[error("unknown key: {0}")]
    UnknownKey(String),
}

impl ActionIdempotencyKey {
    /// New.
    pub fn new(retention_ms: u64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            retention_ms,
            ledger: BTreeMap::new(),
        }
    }

    /// Submit.
    pub fn submit(&mut self, key: &str, now_ms: u64) -> Result<SubmitVerdict, LedgerError> {
        if key.is_empty() { return Err(LedgerError::EmptyKey); }
        if let Some(e) = self.ledger.get(key) {
            return Ok(SubmitVerdict::Replay {
                first_seen_ts_ms: e.first_seen_ts_ms,
                recorded_outcome: e.outcome.clone(),
            });
        }
        self.ledger.insert(key.into(), Entry {
            first_seen_ts_ms: now_ms,
            outcome: None,
        });
        Ok(SubmitVerdict::Fresh { recorded_at_ms: now_ms })
    }

    /// Attach outcome.
    pub fn complete(&mut self, key: &str, outcome: Outcome) -> Result<(), LedgerError> {
        let e = self.ledger.get_mut(key).ok_or_else(|| LedgerError::UnknownKey(key.into()))?;
        e.outcome = Some(outcome);
        Ok(())
    }

    /// Drop expired entries.
    pub fn rotate(&mut self, now_ms: u64) {
        let r = self.retention_ms;
        self.ledger.retain(|_, e| now_ms.saturating_sub(e.first_seen_ts_ms) <= r);
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), LedgerError> {
        if self.schema_version != SCHEMA_VERSION { return Err(LedgerError::SchemaMismatch); }
        for k in self.ledger.keys() {
            if k.is_empty() { return Err(LedgerError::EmptyKey); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_submit_is_fresh() {
        let mut l = ActionIdempotencyKey::new(60_000);
        let v = l.submit("k1", 1000).unwrap();
        assert_eq!(v, SubmitVerdict::Fresh { recorded_at_ms: 1000 });
    }

    #[test]
    fn second_submit_is_replay() {
        let mut l = ActionIdempotencyKey::new(60_000);
        l.submit("k1", 1000).unwrap();
        let v = l.submit("k1", 2000).unwrap();
        assert_eq!(v, SubmitVerdict::Replay {
            first_seen_ts_ms: 1000,
            recorded_outcome: None,
        });
    }

    #[test]
    fn complete_then_replay_carries_outcome() {
        let mut l = ActionIdempotencyKey::new(60_000);
        l.submit("k1", 1000).unwrap();
        l.complete("k1", "ok".into()).unwrap();
        let v = l.submit("k1", 2000).unwrap();
        match v {
            SubmitVerdict::Replay { recorded_outcome, .. } => {
                assert_eq!(recorded_outcome.as_deref(), Some("ok"));
            }
            _ => panic!("expected replay with outcome"),
        }
    }

    #[test]
    fn complete_unknown_rejected() {
        let mut l = ActionIdempotencyKey::new(60_000);
        assert!(matches!(l.complete("missing", "ok".into()).unwrap_err(), LedgerError::UnknownKey(_)));
    }

    #[test]
    fn empty_key_rejected() {
        let mut l = ActionIdempotencyKey::new(60_000);
        assert!(matches!(l.submit("", 0).unwrap_err(), LedgerError::EmptyKey));
    }

    #[test]
    fn rotate_drops_old() {
        let mut l = ActionIdempotencyKey::new(60_000);
        l.submit("k1", 1000).unwrap();
        l.rotate(120_000);
        assert!(l.ledger.is_empty());
    }

    #[test]
    fn distinct_keys_independent() {
        let mut l = ActionIdempotencyKey::new(60_000);
        l.submit("k1", 1000).unwrap();
        assert_eq!(l.submit("k2", 2000).unwrap(), SubmitVerdict::Fresh { recorded_at_ms: 2000 });
    }

    #[test]
    fn schema_drift_rejected() {
        let mut l = ActionIdempotencyKey::new(60_000);
        l.schema_version = "9.9.9".into();
        assert!(matches!(l.validate().unwrap_err(), LedgerError::SchemaMismatch));
    }

    #[test]
    fn idempotency_serde_roundtrip() {
        let mut l = ActionIdempotencyKey::new(60_000);
        l.submit("k1", 1000).unwrap();
        l.complete("k1", "ok".into()).unwrap();
        let j = serde_json::to_string(&l).unwrap();
        let back: ActionIdempotencyKey = serde_json::from_str(&j).unwrap();
        assert_eq!(l, back);
    }
}
