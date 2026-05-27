//! `selfdef-quarantine-cause-taxonomy` — 8 canonical quarantine causes.
//!
//! Each cause declares:
//! - `severity_floor`  — minimum Severity the cause implies
//! - `requires_operator_clear` — operator must explicitly clear (true)
//!   or quarantine auto-clears once the condition resolves (false)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_incident_classifier::Severity;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// 8 canonical quarantine causes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QuarantineCause {
    /// Action attempted in violation of an IPS policy gate.
    PolicyViolation,
    /// Subject emitted a payload that failed schema validation.
    SchemaInvalid,
    /// Collector exceeded its hard EPS ceiling.
    HardEpsBreach,
    /// Anomaly hint of Warn-or-higher severity matched the subject.
    AnomalyTriggered,
    /// Mirror-vs-source drift detected (MS042).
    DriftDetected,
    /// Subject submitted a request without a valid MS003 signature.
    UnsignedRequest,
    /// Subject's trust score is below the floor.
    UntrustedSubject,
    /// Operator manually quarantined.
    ManualOperator,
}

/// Per-cause policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CausePolicy {
    /// Cause.
    pub cause: QuarantineCause,
    /// Severity floor.
    pub severity_floor: Severity,
    /// Operator must explicitly clear.
    pub requires_operator_clear: bool,
}

/// Taxonomy envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CauseTaxonomy {
    /// Schema version.
    pub schema_version: String,
    /// 8 policies.
    pub policies: Vec<CausePolicy>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CauseError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 8.
    #[error("cause count {0} != 8 canonical")]
    CountInvalid(usize),
    /// Missing.
    #[error("missing cause: {0:?}")]
    Missing(QuarantineCause),
}

const REQUIRED: [QuarantineCause; 8] = [
    QuarantineCause::PolicyViolation,
    QuarantineCause::SchemaInvalid,
    QuarantineCause::HardEpsBreach,
    QuarantineCause::AnomalyTriggered,
    QuarantineCause::DriftDetected,
    QuarantineCause::UnsignedRequest,
    QuarantineCause::UntrustedSubject,
    QuarantineCause::ManualOperator,
];

impl CauseTaxonomy {
    /// Canonical taxonomy.
    pub fn canonical() -> Self {
        let policies = vec![
            CausePolicy {
                cause: QuarantineCause::PolicyViolation,
                severity_floor: Severity::Critical,
                requires_operator_clear: true,
            },
            CausePolicy {
                cause: QuarantineCause::SchemaInvalid,
                severity_floor: Severity::Warn,
                requires_operator_clear: false,
            },
            CausePolicy {
                cause: QuarantineCause::HardEpsBreach,
                severity_floor: Severity::Warn,
                requires_operator_clear: false,
            },
            CausePolicy {
                cause: QuarantineCause::AnomalyTriggered,
                severity_floor: Severity::Warn,
                requires_operator_clear: true,
            },
            CausePolicy {
                cause: QuarantineCause::DriftDetected,
                severity_floor: Severity::Critical,
                requires_operator_clear: true,
            },
            CausePolicy {
                cause: QuarantineCause::UnsignedRequest,
                severity_floor: Severity::Critical,
                requires_operator_clear: true,
            },
            CausePolicy {
                cause: QuarantineCause::UntrustedSubject,
                severity_floor: Severity::Warn,
                requires_operator_clear: false,
            },
            CausePolicy {
                cause: QuarantineCause::ManualOperator,
                severity_floor: Severity::Notice,
                requires_operator_clear: true,
            },
        ];
        Self {
            schema_version: SCHEMA_VERSION.into(),
            policies,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CauseError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CauseError::SchemaMismatch);
        }
        if self.policies.len() != 8 {
            return Err(CauseError::CountInvalid(self.policies.len()));
        }
        for c in REQUIRED {
            if !self.policies.iter().any(|p| p.cause == c) {
                return Err(CauseError::Missing(c));
            }
        }
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, c: QuarantineCause) -> Option<&CausePolicy> {
        self.policies.iter().find(|p| p.cause == c)
    }

    /// True if this cause must be cleared by the operator (never auto-clears).
    pub fn requires_operator_clear(&self, c: QuarantineCause) -> bool {
        matches!(self.get(c), Some(p) if p.requires_operator_clear)
    }

    /// Severity floor for this cause.
    pub fn severity_floor(&self, c: QuarantineCause) -> Severity {
        self.get(c)
            .map(|p| p.severity_floor)
            .unwrap_or(Severity::Info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        CauseTaxonomy::canonical().validate().unwrap();
    }

    #[test]
    fn eight_causes_present() {
        let t = CauseTaxonomy::canonical();
        for c in REQUIRED {
            assert!(t.get(c).is_some(), "missing {c:?}");
        }
    }

    #[test]
    fn policy_violation_critical_operator_clear() {
        let t = CauseTaxonomy::canonical();
        assert_eq!(
            t.severity_floor(QuarantineCause::PolicyViolation),
            Severity::Critical
        );
        assert!(t.requires_operator_clear(QuarantineCause::PolicyViolation));
    }

    #[test]
    fn hard_eps_auto_clears() {
        let t = CauseTaxonomy::canonical();
        assert!(!t.requires_operator_clear(QuarantineCause::HardEpsBreach));
    }

    #[test]
    fn manual_operator_is_notice() {
        let t = CauseTaxonomy::canonical();
        assert_eq!(
            t.severity_floor(QuarantineCause::ManualOperator),
            Severity::Notice
        );
        assert!(t.requires_operator_clear(QuarantineCause::ManualOperator));
    }

    #[test]
    fn unsigned_critical() {
        let t = CauseTaxonomy::canonical();
        assert_eq!(
            t.severity_floor(QuarantineCause::UnsignedRequest),
            Severity::Critical
        );
    }

    #[test]
    fn count_invalid_caught() {
        let mut t = CauseTaxonomy::canonical();
        t.policies.pop();
        assert!(matches!(
            t.validate().unwrap_err(),
            CauseError::CountInvalid(7)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = CauseTaxonomy::canonical();
        t.schema_version = "9.9.9".into();
        assert!(matches!(
            t.validate().unwrap_err(),
            CauseError::SchemaMismatch
        ));
    }

    #[test]
    fn cause_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&QuarantineCause::PolicyViolation).unwrap(),
            "\"policy-violation\""
        );
        assert_eq!(
            serde_json::to_string(&QuarantineCause::HardEpsBreach).unwrap(),
            "\"hard-eps-breach\""
        );
        assert_eq!(
            serde_json::to_string(&QuarantineCause::UnsignedRequest).unwrap(),
            "\"unsigned-request\""
        );
    }

    #[test]
    fn taxonomy_serde_roundtrip() {
        let t = CauseTaxonomy::canonical();
        let j = serde_json::to_string(&t).unwrap();
        let back: CauseTaxonomy = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
