//! `selfdef-anomaly-hint` — non-blocking deviation envelope.
//!
//! Each `AnomalyHint` describes one detected deviation with:
//! - `class` — 6 canonical anomaly classes
//! - `severity` — incident classifier severity (Info..Emergency)
//! - `trace_id` — M049 link
//! - `observed` + `baseline` — short operator-readable summary strings
//! - `score` — heuristic 0..100 confidence
//!
//! Hints are dispatched through the notifier chain per severity; they
//! never themselves quarantine subjects or revoke grants.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_incident_classifier::Severity;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// 6 anomaly classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnomalyClass {
    /// Sudden risk-class promotion (Low → Critical in a single decision).
    RiskClassJump,
    /// Subject used a model_provider never seen before.
    NovelProvider,
    /// Activity outside the operator's usual hours.
    OffHourActivity,
    /// Subject hit N consecutive deny outcomes.
    RepeatDeny,
    /// Capability word differs from the issued grant.
    CapabilityWordDrift,
    /// Subject is below trust-score floor.
    UntrustedSubject,
}

/// One anomaly hint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnomalyHint {
    /// Schema version.
    pub schema_version: String,
    /// Class.
    pub class: AnomalyClass,
    /// Severity.
    pub severity: Severity,
    /// M049 trace_id.
    pub trace_id: String,
    /// Subject id.
    pub subject: String,
    /// ISO-8601 UTC.
    pub at: String,
    /// Observed value (short string).
    pub observed: String,
    /// Baseline value (short string).
    pub baseline: String,
    /// 0..=100 confidence.
    pub score: u8,
}

/// Errors.
#[derive(Debug, Error)]
pub enum AnomalyError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Score out of range.
    #[error("score {0} out of 0..=100")]
    ScoreOutOfRange(u8),
    /// Empty subject.
    #[error("subject missing")]
    MissingSubject,
    /// Empty trace_id.
    #[error("trace_id missing")]
    MissingTraceId,
    /// Empty timestamp.
    #[error("at missing")]
    MissingTimestamp,
    /// Empty observed.
    #[error("observed missing")]
    MissingObserved,
}

impl AnomalyHint {
    /// New hint with defaults filled in.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class: AnomalyClass,
        severity: Severity,
        trace_id: &str,
        subject: &str,
        at: &str,
        observed: &str,
        baseline: &str,
        score: u8,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            class,
            severity,
            trace_id: trace_id.into(),
            subject: subject.into(),
            at: at.into(),
            observed: observed.into(),
            baseline: baseline.into(),
            score,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), AnomalyError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(AnomalyError::SchemaMismatch);
        }
        if self.score > 100 {
            return Err(AnomalyError::ScoreOutOfRange(self.score));
        }
        if self.subject.is_empty() {
            return Err(AnomalyError::MissingSubject);
        }
        if self.trace_id.is_empty() {
            return Err(AnomalyError::MissingTraceId);
        }
        if self.at.is_empty() {
            return Err(AnomalyError::MissingTimestamp);
        }
        if self.observed.is_empty() {
            return Err(AnomalyError::MissingObserved);
        }
        Ok(())
    }

    /// True if this hint should be auto-promoted to a notifier dispatch.
    pub fn dispatch_warranted(&self) -> bool {
        self.score >= 50 && self.severity >= Severity::Warn
    }
}

/// Canonical severity for an anomaly class.
pub fn canonical_severity(class: AnomalyClass) -> Severity {
    match class {
        AnomalyClass::RiskClassJump => Severity::Critical,
        AnomalyClass::CapabilityWordDrift => Severity::Critical,
        AnomalyClass::UntrustedSubject => Severity::Warn,
        AnomalyClass::NovelProvider => Severity::Notice,
        AnomalyClass::RepeatDeny => Severity::Warn,
        AnomalyClass::OffHourActivity => Severity::Notice,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(class: AnomalyClass, score: u8) -> AnomalyHint {
        AnomalyHint::new(
            class,
            canonical_severity(class),
            "tr-1",
            "op",
            "t",
            "observed-val",
            "baseline-val",
            score,
        )
    }

    #[test]
    fn ok_hint_validates() {
        h(AnomalyClass::RiskClassJump, 80).validate().unwrap();
    }

    #[test]
    fn score_out_of_range_caught() {
        let mut x = h(AnomalyClass::RiskClassJump, 80);
        x.score = 101;
        assert!(matches!(
            x.validate().unwrap_err(),
            AnomalyError::ScoreOutOfRange(101)
        ));
    }

    #[test]
    fn missing_subject_caught() {
        let mut x = h(AnomalyClass::RiskClassJump, 80);
        x.subject = String::new();
        assert!(matches!(
            x.validate().unwrap_err(),
            AnomalyError::MissingSubject
        ));
    }

    #[test]
    fn missing_trace_id_caught() {
        let mut x = h(AnomalyClass::RiskClassJump, 80);
        x.trace_id = String::new();
        assert!(matches!(
            x.validate().unwrap_err(),
            AnomalyError::MissingTraceId
        ));
    }

    #[test]
    fn missing_observed_caught() {
        let mut x = h(AnomalyClass::RiskClassJump, 80);
        x.observed = String::new();
        assert!(matches!(
            x.validate().unwrap_err(),
            AnomalyError::MissingObserved
        ));
    }

    #[test]
    fn dispatch_only_at_warn_plus_and_score_50() {
        // RiskClassJump = Critical, score 80 → dispatch
        assert!(h(AnomalyClass::RiskClassJump, 80).dispatch_warranted());
        // Score 40 → no dispatch
        assert!(!h(AnomalyClass::RiskClassJump, 40).dispatch_warranted());
        // NovelProvider = Notice → no dispatch regardless of score
        assert!(!h(AnomalyClass::NovelProvider, 99).dispatch_warranted());
        // OffHourActivity = Notice → no dispatch
        assert!(!h(AnomalyClass::OffHourActivity, 80).dispatch_warranted());
        // RepeatDeny = Warn, score 60 → dispatch
        assert!(h(AnomalyClass::RepeatDeny, 60).dispatch_warranted());
    }

    #[test]
    fn canonical_severity_map() {
        assert_eq!(
            canonical_severity(AnomalyClass::RiskClassJump),
            Severity::Critical
        );
        assert_eq!(
            canonical_severity(AnomalyClass::CapabilityWordDrift),
            Severity::Critical
        );
        assert_eq!(
            canonical_severity(AnomalyClass::UntrustedSubject),
            Severity::Warn
        );
        assert_eq!(canonical_severity(AnomalyClass::RepeatDeny), Severity::Warn);
        assert_eq!(
            canonical_severity(AnomalyClass::NovelProvider),
            Severity::Notice
        );
        assert_eq!(
            canonical_severity(AnomalyClass::OffHourActivity),
            Severity::Notice
        );
    }

    #[test]
    fn schema_drift_rejected() {
        let mut x = h(AnomalyClass::RiskClassJump, 80);
        x.schema_version = "9.9.9".into();
        assert!(matches!(
            x.validate().unwrap_err(),
            AnomalyError::SchemaMismatch
        ));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&AnomalyClass::RiskClassJump).unwrap(),
            "\"risk-class-jump\""
        );
        assert_eq!(
            serde_json::to_string(&AnomalyClass::NovelProvider).unwrap(),
            "\"novel-provider\""
        );
        assert_eq!(
            serde_json::to_string(&AnomalyClass::CapabilityWordDrift).unwrap(),
            "\"capability-word-drift\""
        );
        assert_eq!(
            serde_json::to_string(&AnomalyClass::OffHourActivity).unwrap(),
            "\"off-hour-activity\""
        );
    }

    #[test]
    fn hint_serde_roundtrip() {
        let x = h(AnomalyClass::RiskClassJump, 75);
        let j = serde_json::to_string(&x).unwrap();
        let back: AnomalyHint = serde_json::from_str(&j).unwrap();
        assert_eq!(x, back);
    }
}
