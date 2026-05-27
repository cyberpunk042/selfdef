//! `selfdef-trust-score-history` — append-only per-subject trust score history.
//!
//! Each entry records a score change with reason. Validator rejects:
//! - empty subject
//! - scores > 100
//! - delta != new_score - old_score
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Reason for the change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScoreReason {
    /// Successful action increased confidence.
    SuccessfulAction,
    /// Anomaly detected, score dropped.
    AnomalyDetected,
    /// Operator manually adjusted.
    OperatorAdjusted,
    /// Cohort promotion adjusted band floor.
    CohortPromoted,
    /// Cohort demotion adjusted band ceiling.
    CohortDemoted,
    /// Time-decay maintenance.
    TimeDecay,
}

/// One history entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoryEntry {
    /// Subject id.
    pub subject: String,
    /// Score before change (0..=100).
    pub old_score: u8,
    /// Score after change (0..=100).
    pub new_score: u8,
    /// Signed delta.
    pub delta: i16,
    /// Reason.
    pub reason: ScoreReason,
    /// ISO-8601 UTC.
    pub at: String,
    /// M049 trace_id linking to the originating event (may be empty for decay).
    pub trace_id: String,
}

/// History envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustScoreHistory {
    /// Schema version.
    pub schema_version: String,
    /// Entries in append order.
    pub entries: Vec<HistoryEntry>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum HistoryError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty subject.
    #[error("entry {0} subject empty")]
    EmptySubject(usize),
    /// Score > 100.
    #[error("entry {idx} score {score} > 100")]
    ScoreOutOfRange {
        /// idx.
        idx: usize,
        /// score.
        score: u8,
    },
    /// Delta doesn't match scores.
    #[error("entry {idx} delta {delta} != {new}-{old} = {expected}")]
    DeltaMismatch {
        /// idx.
        idx: usize,
        /// delta.
        delta: i16,
        /// new.
        new: u8,
        /// old.
        old: u8,
        /// expected.
        expected: i16,
    },
    /// Empty timestamp.
    #[error("entry {0} at empty")]
    EmptyTimestamp(usize),
}

impl TrustScoreHistory {
    /// New empty.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            entries: Vec::new(),
        }
    }

    /// Append an entry. Computes delta automatically + validates.
    pub fn record(
        &mut self,
        subject: &str,
        old_score: u8,
        new_score: u8,
        reason: ScoreReason,
        at: &str,
        trace_id: &str,
    ) -> Result<(), HistoryError> {
        if subject.is_empty() {
            return Err(HistoryError::EmptySubject(self.entries.len()));
        }
        if at.is_empty() {
            return Err(HistoryError::EmptyTimestamp(self.entries.len()));
        }
        if old_score > 100 {
            return Err(HistoryError::ScoreOutOfRange {
                idx: self.entries.len(),
                score: old_score,
            });
        }
        if new_score > 100 {
            return Err(HistoryError::ScoreOutOfRange {
                idx: self.entries.len(),
                score: new_score,
            });
        }
        let delta = new_score as i16 - old_score as i16;
        self.entries.push(HistoryEntry {
            subject: subject.into(),
            old_score,
            new_score,
            delta,
            reason,
            at: at.into(),
            trace_id: trace_id.into(),
        });
        Ok(())
    }

    /// Latest score for subject.
    pub fn latest(&self, subject: &str) -> Option<u8> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.subject == subject)
            .map(|e| e.new_score)
    }

    /// Average delta across all entries for subject.
    pub fn average_delta(&self, subject: &str) -> f32 {
        let v: Vec<&HistoryEntry> = self
            .entries
            .iter()
            .filter(|e| e.subject == subject)
            .collect();
        if v.is_empty() {
            return 0.0;
        }
        let sum: i32 = v.iter().map(|e| e.delta as i32).sum();
        sum as f32 / v.len() as f32
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), HistoryError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(HistoryError::SchemaMismatch);
        }
        for (idx, e) in self.entries.iter().enumerate() {
            if e.subject.is_empty() {
                return Err(HistoryError::EmptySubject(idx));
            }
            if e.at.is_empty() {
                return Err(HistoryError::EmptyTimestamp(idx));
            }
            if e.old_score > 100 {
                return Err(HistoryError::ScoreOutOfRange {
                    idx,
                    score: e.old_score,
                });
            }
            if e.new_score > 100 {
                return Err(HistoryError::ScoreOutOfRange {
                    idx,
                    score: e.new_score,
                });
            }
            let expected = e.new_score as i16 - e.old_score as i16;
            if e.delta != expected {
                return Err(HistoryError::DeltaMismatch {
                    idx,
                    delta: e.delta,
                    new: e.new_score,
                    old: e.old_score,
                    expected,
                });
            }
        }
        Ok(())
    }
}

impl Default for TrustScoreHistory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_history_validates() {
        TrustScoreHistory::new().validate().unwrap();
    }

    #[test]
    fn record_increments_history() {
        let mut h = TrustScoreHistory::new();
        h.record("alice", 50, 55, ScoreReason::SuccessfulAction, "t1", "tr-1")
            .unwrap();
        h.record("alice", 55, 60, ScoreReason::SuccessfulAction, "t2", "tr-2")
            .unwrap();
        assert_eq!(h.latest("alice"), Some(60));
        h.validate().unwrap();
    }

    #[test]
    fn empty_subject_rejected() {
        let mut h = TrustScoreHistory::new();
        assert!(matches!(
            h.record("", 50, 55, ScoreReason::SuccessfulAction, "t", "tr")
                .unwrap_err(),
            HistoryError::EmptySubject(_)
        ));
    }

    #[test]
    fn score_out_of_range_rejected() {
        let mut h = TrustScoreHistory::new();
        assert!(matches!(
            h.record("a", 200, 50, ScoreReason::SuccessfulAction, "t", "tr")
                .unwrap_err(),
            HistoryError::ScoreOutOfRange { .. }
        ));
    }

    #[test]
    fn delta_mismatch_caught_in_validate() {
        let mut h = TrustScoreHistory::new();
        h.record("alice", 50, 55, ScoreReason::SuccessfulAction, "t", "tr")
            .unwrap();
        h.entries[0].delta = 99; // tamper
        assert!(matches!(
            h.validate().unwrap_err(),
            HistoryError::DeltaMismatch { .. }
        ));
    }

    #[test]
    fn latest_returns_none_for_unknown() {
        let h = TrustScoreHistory::new();
        assert_eq!(h.latest("nope"), None);
    }

    #[test]
    fn average_delta() {
        let mut h = TrustScoreHistory::new();
        h.record("alice", 50, 55, ScoreReason::SuccessfulAction, "t1", "tr")
            .unwrap();
        h.record("alice", 55, 60, ScoreReason::SuccessfulAction, "t2", "tr")
            .unwrap();
        h.record("alice", 60, 55, ScoreReason::AnomalyDetected, "t3", "tr")
            .unwrap();
        // (+5, +5, -5) → avg = 5/3 = 1.666...
        assert!((h.average_delta("alice") - 5.0 / 3.0).abs() < 0.001);
        assert_eq!(h.average_delta("bob"), 0.0);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut h = TrustScoreHistory::new();
        h.schema_version = "9.9.9".into();
        assert!(matches!(
            h.validate().unwrap_err(),
            HistoryError::SchemaMismatch
        ));
    }

    #[test]
    fn reason_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&ScoreReason::SuccessfulAction).unwrap(),
            "\"successful-action\""
        );
        assert_eq!(
            serde_json::to_string(&ScoreReason::TimeDecay).unwrap(),
            "\"time-decay\""
        );
    }

    #[test]
    fn history_serde_roundtrip() {
        let mut h = TrustScoreHistory::new();
        h.record("alice", 50, 55, ScoreReason::SuccessfulAction, "t", "tr")
            .unwrap();
        let j = serde_json::to_string(&h).unwrap();
        let back: TrustScoreHistory = serde_json::from_str(&j).unwrap();
        assert_eq!(h, back);
    }
}
