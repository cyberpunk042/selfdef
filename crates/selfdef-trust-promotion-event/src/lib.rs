//! `selfdef-trust-promotion-event` — operator-initiated cohort change log.
//!
//! Each entry records the (subject, from, to, kind, reason, actor,
//! trace_id, at). Promotion direction is enforced via subject-cohort's
//! `promote()`; Demotion is the reverse and allowed.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_subject_cohort::Cohort;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PromotionKind {
    /// Move up.
    Promotion,
    /// Move down.
    Demotion,
}

/// Reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PromotionReason {
    /// Time-based earned trust.
    Earned,
    /// Operator vouched.
    OperatorVouched,
    /// Post-incident demotion.
    PostIncident,
    /// Repeated denies caused demotion.
    RepeatedDenies,
    /// Initial onboarding to a higher cohort.
    Onboarding,
}

/// Entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromotionEntry {
    /// Subject id.
    pub subject: String,
    /// From cohort.
    pub from: Cohort,
    /// To cohort.
    pub to: Cohort,
    /// Kind.
    pub kind: PromotionKind,
    /// Reason.
    pub reason: PromotionReason,
    /// Operator MS003 fingerprint.
    pub actor: String,
    /// ISO-8601 UTC.
    pub at: String,
    /// M049 trace_id.
    pub trace_id: String,
}

/// Log envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromotionLog {
    /// Schema version.
    pub schema_version: String,
    /// Entries.
    pub entries: Vec<PromotionEntry>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum PromotionError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty subject.
    #[error("entry {0} missing subject")]
    MissingSubject(usize),
    /// Empty actor.
    #[error("entry {0} missing actor")]
    MissingActor(usize),
    /// Empty trace_id.
    #[error("entry {0} missing trace_id")]
    MissingTraceId(usize),
    /// Empty timestamp.
    #[error("entry {0} missing at")]
    MissingTimestamp(usize),
    /// from == to.
    #[error("entry {idx} no-op: {cohort:?}")]
    NoOp {
        /// idx.
        idx: usize,
        /// cohort.
        cohort: Cohort,
    },
    /// Kind disagrees with cohort direction.
    #[error("entry {idx} kind {kind:?} disagrees with direction (from {from:?} -> to {to:?})")]
    KindMismatch {
        /// idx.
        idx: usize,
        /// kind.
        kind: PromotionKind,
        /// from.
        from: Cohort,
        /// to.
        to: Cohort,
    },
}

impl PromotionLog {
    /// New empty.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            entries: Vec::new(),
        }
    }

    /// Append a promotion entry; runs kind/direction check.
    pub fn record(&mut self, e: PromotionEntry) -> Result<(), PromotionError> {
        if e.subject.is_empty() {
            return Err(PromotionError::MissingSubject(self.entries.len()));
        }
        if e.actor.is_empty() {
            return Err(PromotionError::MissingActor(self.entries.len()));
        }
        if e.trace_id.is_empty() {
            return Err(PromotionError::MissingTraceId(self.entries.len()));
        }
        if e.at.is_empty() {
            return Err(PromotionError::MissingTimestamp(self.entries.len()));
        }
        if e.from == e.to {
            return Err(PromotionError::NoOp {
                idx: self.entries.len(),
                cohort: e.from,
            });
        }
        let going_up = e.to > e.from;
        let kind_says_up = e.kind == PromotionKind::Promotion;
        if going_up != kind_says_up {
            return Err(PromotionError::KindMismatch {
                idx: self.entries.len(),
                kind: e.kind,
                from: e.from,
                to: e.to,
            });
        }
        self.entries.push(e);
        Ok(())
    }

    /// Count by reason.
    pub fn count_by_reason(&self, reason: PromotionReason) -> usize {
        self.entries.iter().filter(|e| e.reason == reason).count()
    }

    /// Latest cohort known for subject (most recent entry's `to`).
    pub fn latest_cohort(&self, subject: &str) -> Option<Cohort> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.subject == subject)
            .map(|e| e.to)
    }

    /// Validate the log.
    pub fn validate(&self) -> Result<(), PromotionError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(PromotionError::SchemaMismatch);
        }
        for (idx, e) in self.entries.iter().enumerate() {
            if e.subject.is_empty() {
                return Err(PromotionError::MissingSubject(idx));
            }
            if e.actor.is_empty() {
                return Err(PromotionError::MissingActor(idx));
            }
            if e.trace_id.is_empty() {
                return Err(PromotionError::MissingTraceId(idx));
            }
            if e.at.is_empty() {
                return Err(PromotionError::MissingTimestamp(idx));
            }
            if e.from == e.to {
                return Err(PromotionError::NoOp {
                    idx,
                    cohort: e.from,
                });
            }
            let going_up = e.to > e.from;
            let kind_says_up = e.kind == PromotionKind::Promotion;
            if going_up != kind_says_up {
                return Err(PromotionError::KindMismatch {
                    idx,
                    kind: e.kind,
                    from: e.from,
                    to: e.to,
                });
            }
        }
        Ok(())
    }
}

impl Default for PromotionLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(
        subject: &str,
        from: Cohort,
        to: Cohort,
        kind: PromotionKind,
        reason: PromotionReason,
    ) -> PromotionEntry {
        PromotionEntry {
            subject: subject.into(),
            from,
            to,
            kind,
            reason,
            actor: "op-fp".into(),
            at: "2026-05-19T03:00:00Z".into(),
            trace_id: "tr-1".into(),
        }
    }

    #[test]
    fn empty_log_validates() {
        PromotionLog::new().validate().unwrap();
    }

    #[test]
    fn record_promotion() {
        let mut l = PromotionLog::new();
        l.record(entry(
            "alice",
            Cohort::Newcomer,
            Cohort::Probationary,
            PromotionKind::Promotion,
            PromotionReason::Earned,
        ))
        .unwrap();
        assert_eq!(l.latest_cohort("alice"), Some(Cohort::Probationary));
    }

    #[test]
    fn record_demotion() {
        let mut l = PromotionLog::new();
        l.record(entry(
            "alice",
            Cohort::Trusted,
            Cohort::Probationary,
            PromotionKind::Demotion,
            PromotionReason::PostIncident,
        ))
        .unwrap();
        assert_eq!(l.latest_cohort("alice"), Some(Cohort::Probationary));
    }

    #[test]
    fn no_op_rejected() {
        let mut l = PromotionLog::new();
        let err = l
            .record(entry(
                "a",
                Cohort::Trusted,
                Cohort::Trusted,
                PromotionKind::Promotion,
                PromotionReason::Earned,
            ))
            .unwrap_err();
        assert!(matches!(err, PromotionError::NoOp { .. }));
    }

    #[test]
    fn kind_mismatch_caught() {
        let mut l = PromotionLog::new();
        // Going down but marked Promotion
        let err = l
            .record(entry(
                "a",
                Cohort::Trusted,
                Cohort::Newcomer,
                PromotionKind::Promotion,
                PromotionReason::PostIncident,
            ))
            .unwrap_err();
        assert!(matches!(err, PromotionError::KindMismatch { .. }));
    }

    #[test]
    fn count_by_reason() {
        let mut l = PromotionLog::new();
        l.record(entry(
            "a",
            Cohort::Newcomer,
            Cohort::Probationary,
            PromotionKind::Promotion,
            PromotionReason::Earned,
        ))
        .unwrap();
        l.record(entry(
            "b",
            Cohort::Newcomer,
            Cohort::Probationary,
            PromotionKind::Promotion,
            PromotionReason::Earned,
        ))
        .unwrap();
        l.record(entry(
            "c",
            Cohort::Probationary,
            Cohort::Trusted,
            PromotionKind::Promotion,
            PromotionReason::OperatorVouched,
        ))
        .unwrap();
        assert_eq!(l.count_by_reason(PromotionReason::Earned), 2);
        assert_eq!(l.count_by_reason(PromotionReason::OperatorVouched), 1);
        assert_eq!(l.count_by_reason(PromotionReason::PostIncident), 0);
    }

    #[test]
    fn latest_cohort_returns_most_recent() {
        let mut l = PromotionLog::new();
        l.record(entry(
            "a",
            Cohort::Newcomer,
            Cohort::Probationary,
            PromotionKind::Promotion,
            PromotionReason::Earned,
        ))
        .unwrap();
        l.record(entry(
            "a",
            Cohort::Probationary,
            Cohort::Trusted,
            PromotionKind::Promotion,
            PromotionReason::OperatorVouched,
        ))
        .unwrap();
        assert_eq!(l.latest_cohort("a"), Some(Cohort::Trusted));
    }

    #[test]
    fn unknown_subject_returns_none() {
        let l = PromotionLog::new();
        assert_eq!(l.latest_cohort("nope"), None);
    }

    #[test]
    fn missing_subject_caught() {
        let mut l = PromotionLog::new();
        let err = l
            .record(entry(
                "",
                Cohort::Newcomer,
                Cohort::Probationary,
                PromotionKind::Promotion,
                PromotionReason::Earned,
            ))
            .unwrap_err();
        assert!(matches!(err, PromotionError::MissingSubject(_)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut l = PromotionLog::new();
        l.schema_version = "9.9.9".into();
        assert!(matches!(
            l.validate().unwrap_err(),
            PromotionError::SchemaMismatch
        ));
    }

    #[test]
    fn reason_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&PromotionReason::Earned).unwrap(),
            "\"earned\""
        );
        assert_eq!(
            serde_json::to_string(&PromotionReason::OperatorVouched).unwrap(),
            "\"operator-vouched\""
        );
        assert_eq!(
            serde_json::to_string(&PromotionReason::RepeatedDenies).unwrap(),
            "\"repeated-denies\""
        );
    }

    #[test]
    fn log_serde_roundtrip() {
        let mut l = PromotionLog::new();
        l.record(entry(
            "a",
            Cohort::Newcomer,
            Cohort::Probationary,
            PromotionKind::Promotion,
            PromotionReason::Earned,
        ))
        .unwrap();
        let j = serde_json::to_string(&l).unwrap();
        let back: PromotionLog = serde_json::from_str(&j).unwrap();
        assert_eq!(l, back);
    }
}
