//! `selfdef-stall-detector` — per-subject stall detection.
//!
//! `observe(subject_id, ts_ms)` records progress (monotonic).
//! `check(subject_id, now, stall_ms)` returns:
//!   * `Active{age_ms}` — age since last observation under threshold.
//!   * `Stalled{age_ms, threshold_ms}` — over threshold.
//!   * `Unknown` — no observation yet.
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
pub struct StallDetector {
    /// Schema version.
    pub schema_version: String,
    /// subject_id → last_ts.
    pub last: BTreeMap<String, u64>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum StallVerdict {
    /// Active.
    Active {
        /// age.
        age_ms: u64,
    },
    /// Stalled.
    Stalled {
        /// age.
        age_ms: u64,
        /// threshold.
        threshold_ms: u64,
    },
    /// Unknown.
    Unknown,
}

/// Errors.
#[derive(Debug, Error)]
pub enum StallError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty subject.
    #[error("subject id empty")]
    EmptySubject,
    /// Non-monotonic.
    #[error("non-monotonic ts: prev {prev} > new {new}")]
    NonMonotonic {
        /// prev.
        prev: u64,
        /// new.
        new: u64,
    },
}

impl StallDetector {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            last: BTreeMap::new(),
        }
    }

    /// Observe.
    pub fn observe(&mut self, subject_id: &str, ts_ms: u64) -> Result<(), StallError> {
        if subject_id.is_empty() {
            return Err(StallError::EmptySubject);
        }
        if let Some(&prev) = self.last.get(subject_id) {
            if ts_ms < prev {
                return Err(StallError::NonMonotonic { prev, new: ts_ms });
            }
        }
        self.last.insert(subject_id.into(), ts_ms);
        Ok(())
    }

    /// Forget a subject (e.g. completed).
    pub fn forget(&mut self, subject_id: &str) -> bool {
        self.last.remove(subject_id).is_some()
    }

    /// Check.
    pub fn check(&self, subject_id: &str, now_ms: u64, stall_ms: u64) -> StallVerdict {
        match self.last.get(subject_id).copied() {
            None => StallVerdict::Unknown,
            Some(prev) => {
                let age = now_ms.saturating_sub(prev);
                if age > stall_ms {
                    StallVerdict::Stalled {
                        age_ms: age,
                        threshold_ms: stall_ms,
                    }
                } else {
                    StallVerdict::Active { age_ms: age }
                }
            }
        }
    }

    /// All stalled subjects at now.
    pub fn stalled_subjects(&self, now_ms: u64, stall_ms: u64) -> Vec<String> {
        self.last
            .iter()
            .filter(|&(_, &t)| now_ms.saturating_sub(t) > stall_ms)
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), StallError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(StallError::SchemaMismatch);
        }
        for k in self.last.keys() {
            if k.is_empty() {
                return Err(StallError::EmptySubject);
            }
        }
        Ok(())
    }
}

impl Default for StallDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_when_no_obs() {
        let s = StallDetector::new();
        assert_eq!(s.check("x", 100, 1000), StallVerdict::Unknown);
    }

    #[test]
    fn active_under_threshold() {
        let mut s = StallDetector::new();
        s.observe("x", 100).unwrap();
        assert!(matches!(
            s.check("x", 500, 1000),
            StallVerdict::Active { age_ms: 400 }
        ));
    }

    #[test]
    fn stalled_past_threshold() {
        let mut s = StallDetector::new();
        s.observe("x", 100).unwrap();
        match s.check("x", 5000, 1000) {
            StallVerdict::Stalled {
                age_ms,
                threshold_ms,
            } => {
                assert_eq!(age_ms, 4900);
                assert_eq!(threshold_ms, 1000);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn nonmonotonic_rejected() {
        let mut s = StallDetector::new();
        s.observe("x", 200).unwrap();
        assert!(matches!(
            s.observe("x", 100).unwrap_err(),
            StallError::NonMonotonic { .. }
        ));
    }

    #[test]
    fn forget_clears() {
        let mut s = StallDetector::new();
        s.observe("x", 100).unwrap();
        assert!(s.forget("x"));
        assert_eq!(s.check("x", 0, 1000), StallVerdict::Unknown);
    }

    #[test]
    fn stalled_subjects_lists() {
        let mut s = StallDetector::new();
        s.observe("a", 100).unwrap();
        s.observe("b", 9000).unwrap();
        let list = s.stalled_subjects(10_000, 1000);
        assert!(list.contains(&"a".to_string()));
        assert!(!list.contains(&"b".to_string()));
    }

    #[test]
    fn empty_subject_rejected() {
        let mut s = StallDetector::new();
        assert!(matches!(
            s.observe("", 0).unwrap_err(),
            StallError::EmptySubject
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = StallDetector::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            StallError::SchemaMismatch
        ));
    }

    #[test]
    fn stall_serde_roundtrip() {
        let mut s = StallDetector::new();
        s.observe("x", 100).unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: StallDetector = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
