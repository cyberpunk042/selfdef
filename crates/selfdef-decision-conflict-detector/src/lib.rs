//! `selfdef-decision-conflict-detector` — divergent-outcome detector.
//!
//! `record(payload_hash, outcome, ts)` appends an outcome observation.
//! `check(payload_hash, now)` returns:
//!   * `Consistent` — all in-window observations agree (or none).
//!   * `Divergent { outcomes }` — at least two distinct outcomes in
//!     the window.
//!   * `Stale` — only observations outside the window.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One observation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Obs {
    /// outcome label.
    pub outcome: String,
    /// ts ms.
    pub ts_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionConflictDetector {
    /// Schema version.
    pub schema_version: String,
    /// Window width (ms).
    pub window_ms: u64,
    /// payload_hash → observations.
    pub ledger: BTreeMap<String, Vec<Obs>>,
}

/// Verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ConflictVerdict {
    /// No conflict.
    Consistent,
    /// Divergent.
    Divergent {
        /// Distinct outcomes observed.
        outcomes: Vec<String>,
    },
    /// Only stale observations.
    Stale,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DetectorError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty hash.
    #[error("payload hash empty")]
    EmptyHash,
    /// Empty outcome.
    #[error("outcome empty")]
    EmptyOutcome,
}

impl DecisionConflictDetector {
    /// New.
    pub fn new(window_ms: u64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            window_ms,
            ledger: BTreeMap::new(),
        }
    }

    /// Record an observation.
    pub fn record(
        &mut self,
        payload_hash: &str,
        outcome: &str,
        ts_ms: u64,
    ) -> Result<(), DetectorError> {
        if payload_hash.is_empty() {
            return Err(DetectorError::EmptyHash);
        }
        if outcome.is_empty() {
            return Err(DetectorError::EmptyOutcome);
        }
        self.ledger
            .entry(payload_hash.into())
            .or_default()
            .push(Obs {
                outcome: outcome.into(),
                ts_ms,
            });
        Ok(())
    }

    /// Check.
    pub fn check(&self, payload_hash: &str, now_ms: u64) -> ConflictVerdict {
        let entries = match self.ledger.get(payload_hash) {
            Some(e) => e,
            None => return ConflictVerdict::Consistent,
        };
        let cutoff = now_ms.saturating_sub(self.window_ms);
        let in_window: BTreeSet<&str> = entries
            .iter()
            .filter(|o| o.ts_ms >= cutoff && o.ts_ms <= now_ms)
            .map(|o| o.outcome.as_str())
            .collect();
        match in_window.len() {
            0 if !entries.is_empty() => ConflictVerdict::Stale,
            0 | 1 => ConflictVerdict::Consistent,
            _ => ConflictVerdict::Divergent {
                outcomes: in_window.into_iter().map(|s| s.to_string()).collect(),
            },
        }
    }

    /// Drop expired entries.
    pub fn rotate(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        for entries in self.ledger.values_mut() {
            entries.retain(|o| o.ts_ms >= cutoff);
        }
        self.ledger.retain(|_, v| !v.is_empty());
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DetectorError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(DetectorError::SchemaMismatch);
        }
        for (k, v) in &self.ledger {
            if k.is_empty() {
                return Err(DetectorError::EmptyHash);
            }
            for o in v {
                if o.outcome.is_empty() {
                    return Err(DetectorError::EmptyOutcome);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consistent_single_outcome() {
        let mut d = DecisionConflictDetector::new(60_000);
        d.record("h1", "Allow", 1000).unwrap();
        d.record("h1", "Allow", 2000).unwrap();
        assert_eq!(d.check("h1", 3000), ConflictVerdict::Consistent);
    }

    #[test]
    fn divergent_two_outcomes() {
        let mut d = DecisionConflictDetector::new(60_000);
        d.record("h1", "Allow", 1000).unwrap();
        d.record("h1", "Deny", 2000).unwrap();
        let v = d.check("h1", 3000);
        match v {
            ConflictVerdict::Divergent { outcomes } => {
                assert!(outcomes.contains(&"Allow".to_string()));
                assert!(outcomes.contains(&"Deny".to_string()));
            }
            _ => panic!("expected divergent"),
        }
    }

    #[test]
    fn stale_when_all_out_of_window() {
        let mut d = DecisionConflictDetector::new(1000);
        d.record("h1", "Allow", 1000).unwrap();
        d.record("h1", "Deny", 1500).unwrap();
        // 10 seconds later, both records are out of window.
        assert_eq!(d.check("h1", 11_000), ConflictVerdict::Stale);
    }

    #[test]
    fn unknown_hash_consistent() {
        let d = DecisionConflictDetector::new(60_000);
        assert_eq!(d.check("missing", 0), ConflictVerdict::Consistent);
    }

    #[test]
    fn empty_hash_rejected() {
        let mut d = DecisionConflictDetector::new(60_000);
        assert!(matches!(
            d.record("", "a", 0).unwrap_err(),
            DetectorError::EmptyHash
        ));
    }

    #[test]
    fn empty_outcome_rejected() {
        let mut d = DecisionConflictDetector::new(60_000);
        assert!(matches!(
            d.record("h", "", 0).unwrap_err(),
            DetectorError::EmptyOutcome
        ));
    }

    #[test]
    fn rotate_drops_old() {
        let mut d = DecisionConflictDetector::new(1000);
        d.record("h1", "Allow", 1000).unwrap();
        d.rotate(10_000);
        assert!(!d.ledger.contains_key("h1"));
    }

    #[test]
    fn divergence_only_within_window() {
        let mut d = DecisionConflictDetector::new(1000);
        // Allow long ago; Deny recent — only Deny is in-window.
        d.record("h1", "Allow", 0).unwrap();
        d.record("h1", "Deny", 10_000).unwrap();
        assert_eq!(d.check("h1", 10_500), ConflictVerdict::Consistent);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut d = DecisionConflictDetector::new(1);
        d.schema_version = "9.9.9".into();
        assert!(matches!(
            d.validate().unwrap_err(),
            DetectorError::SchemaMismatch
        ));
    }

    #[test]
    fn detector_serde_roundtrip() {
        let mut d = DecisionConflictDetector::new(60_000);
        d.record("h1", "Allow", 1000).unwrap();
        let j = serde_json::to_string(&d).unwrap();
        let back: DecisionConflictDetector = serde_json::from_str(&j).unwrap();
        assert_eq!(d, back);
    }
}
