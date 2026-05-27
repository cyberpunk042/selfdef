//! `selfdef-bus-deadletter-policy` — DLQ for failed bus deliveries.
//!
//! `record_attempt(event_id, ok)`:
//!   * ok=true → clears the counter, returns `Delivered`.
//!   * ok=false → bumps the counter; returns `Retry{attempts}` while
//!     attempts < max_attempts, else `DeadLetter{attempts}` and the
//!     event is parked.
//!
//! `revive(event_id)` clears the DLQ flag and resets the counter so
//! the operator can retry by hand.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-event tracking.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventTrack {
    /// Attempts to date.
    pub attempts: u32,
    /// Whether DLQ’d.
    pub dead_lettered: bool,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BusDeadletterPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Max attempts before DLQ.
    pub max_attempts: u32,
    /// event_id → track.
    pub tracks: BTreeMap<String, EventTrack>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AttemptVerdict {
    /// Delivered successfully — counter cleared.
    Delivered,
    /// Failed; will retry.
    Retry {
        /// attempts so far.
        attempts: u32,
    },
    /// Failed; max reached. Event moved to DLQ.
    DeadLetter {
        /// attempts at DLQ time.
        attempts: u32,
    },
    /// Already DLQ’d; further attempts ignored unless revived.
    AlreadyDead,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DlqError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty event id.
    #[error("event id empty")]
    EmptyId,
    /// max_attempts must be > 0.
    #[error("max_attempts must be > 0")]
    ZeroAttempts,
}

impl BusDeadletterPolicy {
    /// New.
    pub fn new(max_attempts: u32) -> Result<Self, DlqError> {
        if max_attempts == 0 {
            return Err(DlqError::ZeroAttempts);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            max_attempts,
            tracks: BTreeMap::new(),
        })
    }

    /// Record an attempt.
    pub fn record_attempt(&mut self, event_id: &str, ok: bool) -> Result<AttemptVerdict, DlqError> {
        if event_id.is_empty() {
            return Err(DlqError::EmptyId);
        }
        let track = self.tracks.entry(event_id.into()).or_insert(EventTrack {
            attempts: 0,
            dead_lettered: false,
        });
        if track.dead_lettered {
            return Ok(AttemptVerdict::AlreadyDead);
        }
        if ok {
            self.tracks.remove(event_id);
            return Ok(AttemptVerdict::Delivered);
        }
        track.attempts = track.attempts.saturating_add(1);
        if track.attempts >= self.max_attempts {
            track.dead_lettered = true;
            Ok(AttemptVerdict::DeadLetter {
                attempts: track.attempts,
            })
        } else {
            Ok(AttemptVerdict::Retry {
                attempts: track.attempts,
            })
        }
    }

    /// Revive a DLQ'd event.
    pub fn revive(&mut self, event_id: &str) -> bool {
        if let Some(track) = self.tracks.get_mut(event_id) {
            if track.dead_lettered {
                self.tracks.remove(event_id);
                return true;
            }
        }
        false
    }

    /// All dead-lettered ids.
    pub fn dead_letter_ids(&self) -> Vec<String> {
        self.tracks
            .iter()
            .filter(|(_, t)| t.dead_lettered)
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DlqError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(DlqError::SchemaMismatch);
        }
        if self.max_attempts == 0 {
            return Err(DlqError::ZeroAttempts);
        }
        for k in self.tracks.keys() {
            if k.is_empty() {
                return Err(DlqError::EmptyId);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_attempts_rejected() {
        assert!(matches!(
            BusDeadletterPolicy::new(0).unwrap_err(),
            DlqError::ZeroAttempts
        ));
    }

    #[test]
    fn delivered_clears() {
        let mut p = BusDeadletterPolicy::new(3).unwrap();
        p.record_attempt("e1", false).unwrap();
        let v = p.record_attempt("e1", true).unwrap();
        assert_eq!(v, AttemptVerdict::Delivered);
        assert!(!p.tracks.contains_key("e1"));
    }

    #[test]
    fn retries_then_dlq() {
        let mut p = BusDeadletterPolicy::new(3).unwrap();
        assert_eq!(
            p.record_attempt("e1", false).unwrap(),
            AttemptVerdict::Retry { attempts: 1 }
        );
        assert_eq!(
            p.record_attempt("e1", false).unwrap(),
            AttemptVerdict::Retry { attempts: 2 }
        );
        let v = p.record_attempt("e1", false).unwrap();
        assert_eq!(v, AttemptVerdict::DeadLetter { attempts: 3 });
    }

    #[test]
    fn already_dead_after_dlq() {
        let mut p = BusDeadletterPolicy::new(1).unwrap();
        p.record_attempt("e1", false).unwrap();
        let v = p.record_attempt("e1", false).unwrap();
        assert_eq!(v, AttemptVerdict::AlreadyDead);
    }

    #[test]
    fn revive_clears_dead() {
        let mut p = BusDeadletterPolicy::new(1).unwrap();
        p.record_attempt("e1", false).unwrap();
        assert!(p.revive("e1"));
        // After revive, attempts start fresh.
        assert_eq!(
            p.record_attempt("e1", false).unwrap(),
            AttemptVerdict::DeadLetter { attempts: 1 }
        );
    }

    #[test]
    fn revive_unknown_returns_false() {
        let mut p = BusDeadletterPolicy::new(1).unwrap();
        assert!(!p.revive("missing"));
    }

    #[test]
    fn dead_letter_ids_reports_only_dlq() {
        let mut p = BusDeadletterPolicy::new(1).unwrap();
        p.record_attempt("a", false).unwrap();
        p.record_attempt("b", false).unwrap();
        p.record_attempt("c", true).unwrap();
        let ids = p.dead_letter_ids();
        assert!(ids.contains(&"a".to_string()));
        assert!(ids.contains(&"b".to_string()));
        assert!(!ids.contains(&"c".to_string()));
    }

    #[test]
    fn empty_id_rejected() {
        let mut p = BusDeadletterPolicy::new(1).unwrap();
        assert!(matches!(
            p.record_attempt("", false).unwrap_err(),
            DlqError::EmptyId
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = BusDeadletterPolicy::new(1).unwrap();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            DlqError::SchemaMismatch
        ));
    }

    #[test]
    fn dlq_serde_roundtrip() {
        let mut p = BusDeadletterPolicy::new(3).unwrap();
        p.record_attempt("e1", false).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: BusDeadletterPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
