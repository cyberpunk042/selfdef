//! `selfdef-mode-pre-flight` — pre-flight check before mode entry.
//!
//! 5 checks: snapshot_fresh, eval_recent, audit_log_healthy,
//! bus_subscribers_wired, boundary_policies_signed. The daemon
//! aggregates failures into a `PreFlightReport`; mode entry only
//! proceeds if `report.all_pass()`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_execution_mode_policy::ExecutionMode;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// 5 pre-flight checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckKind {
    /// Snapshot taken recently.
    SnapshotFresh,
    /// Eval suite passed recently.
    EvalRecent,
    /// Audit log healthy (no chain break, not full).
    AuditLogHealthy,
    /// All 9 bus subscribers wired.
    BusSubscribersWired,
    /// Boundary policy packs signed + non-empty.
    BoundaryPoliciesSigned,
}

/// One check result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckResult {
    /// Kind.
    pub kind: CheckKind,
    /// True if check passed.
    pub passed: bool,
    /// Human-readable detail (empty when passed).
    pub detail: String,
}

/// Pre-flight report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreFlightReport {
    /// Schema version.
    pub schema_version: String,
    /// Target mode.
    pub target_mode: ExecutionMode,
    /// 5 results.
    pub results: Vec<CheckResult>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum PreFlightError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 5.
    #[error("results count {0} != 5")]
    CountInvalid(usize),
    /// Missing.
    #[error("missing check kind: {0:?}")]
    Missing(CheckKind),
    /// Refused at boundary.
    #[error("pre-flight failed for {mode:?}: {failures:?}")]
    Refused {
        /// mode.
        mode: ExecutionMode,
        /// failures.
        failures: Vec<CheckKind>,
    },
}

const REQUIRED: [CheckKind; 5] = [
    CheckKind::SnapshotFresh,
    CheckKind::EvalRecent,
    CheckKind::AuditLogHealthy,
    CheckKind::BusSubscribersWired,
    CheckKind::BoundaryPoliciesSigned,
];

impl PreFlightReport {
    /// Build a report from check results.
    pub fn build(target_mode: ExecutionMode, results: Vec<CheckResult>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            target_mode,
            results,
        }
    }

    /// All 5 checks passed?
    pub fn all_pass(&self) -> bool {
        self.results.iter().all(|r| r.passed)
    }

    /// Failed check kinds.
    pub fn failures(&self) -> Vec<CheckKind> {
        self.results
            .iter()
            .filter(|r| !r.passed)
            .map(|r| r.kind)
            .collect()
    }

    /// Assert all passed — else `Refused`.
    pub fn assert_pass(&self) -> Result<(), PreFlightError> {
        self.validate()?;
        if !self.all_pass() {
            return Err(PreFlightError::Refused {
                mode: self.target_mode,
                failures: self.failures(),
            });
        }
        Ok(())
    }

    /// Validate structure.
    pub fn validate(&self) -> Result<(), PreFlightError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(PreFlightError::SchemaMismatch);
        }
        if self.results.len() != 5 {
            return Err(PreFlightError::CountInvalid(self.results.len()));
        }
        for k in REQUIRED {
            if !self.results.iter().any(|r| r.kind == k) {
                return Err(PreFlightError::Missing(k));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(kind: CheckKind, passed: bool) -> CheckResult {
        CheckResult {
            kind,
            passed,
            detail: if passed { String::new() } else { "fail".into() },
        }
    }

    fn all_pass_report(mode: ExecutionMode) -> PreFlightReport {
        PreFlightReport::build(mode, REQUIRED.iter().map(|k| check(*k, true)).collect())
    }

    #[test]
    fn all_pass_report_passes() {
        let r = all_pass_report(ExecutionMode::Execute);
        r.assert_pass().unwrap();
        assert!(r.all_pass());
        assert!(r.failures().is_empty());
    }

    #[test]
    fn any_failure_refused() {
        let mut r = all_pass_report(ExecutionMode::Execute);
        r.results[0] = check(CheckKind::SnapshotFresh, false);
        let err = r.assert_pass().unwrap_err();
        match err {
            PreFlightError::Refused { mode, failures } => {
                assert_eq!(mode, ExecutionMode::Execute);
                assert_eq!(failures, vec![CheckKind::SnapshotFresh]);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn multiple_failures_listed() {
        let mut r = all_pass_report(ExecutionMode::Execute);
        r.results[0] = check(CheckKind::SnapshotFresh, false);
        r.results[2] = check(CheckKind::AuditLogHealthy, false);
        match r.assert_pass().unwrap_err() {
            PreFlightError::Refused { failures, .. } => {
                assert_eq!(failures.len(), 2);
                assert!(failures.contains(&CheckKind::SnapshotFresh));
                assert!(failures.contains(&CheckKind::AuditLogHealthy));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn count_invalid_caught() {
        let mut r = all_pass_report(ExecutionMode::Execute);
        r.results.pop();
        assert!(matches!(
            r.validate().unwrap_err(),
            PreFlightError::CountInvalid(4)
        ));
    }

    #[test]
    fn missing_check_caught() {
        let mut r = all_pass_report(ExecutionMode::Execute);
        // Replace SnapshotFresh with duplicate EvalRecent.
        for c in r.results.iter_mut() {
            if c.kind == CheckKind::SnapshotFresh {
                c.kind = CheckKind::EvalRecent;
            }
        }
        assert!(matches!(
            r.validate().unwrap_err(),
            PreFlightError::Missing(CheckKind::SnapshotFresh)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = all_pass_report(ExecutionMode::Execute);
        r.schema_version = "9.9.9".into();
        assert!(matches!(
            r.validate().unwrap_err(),
            PreFlightError::SchemaMismatch
        ));
    }

    #[test]
    fn check_kind_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&CheckKind::SnapshotFresh).unwrap(),
            "\"snapshot-fresh\""
        );
        assert_eq!(
            serde_json::to_string(&CheckKind::AuditLogHealthy).unwrap(),
            "\"audit-log-healthy\""
        );
        assert_eq!(
            serde_json::to_string(&CheckKind::BoundaryPoliciesSigned).unwrap(),
            "\"boundary-policies-signed\""
        );
    }

    #[test]
    fn report_serde_roundtrip() {
        let r = all_pass_report(ExecutionMode::Execute);
        let j = serde_json::to_string(&r).unwrap();
        let back: PreFlightReport = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
