//! `selfdef-substrate-cold-boot-policy` — boot-checklist authority.
//!
//! Ordered checklist. first_failure() returns the first BootStep
//! that hasn't passed. all_passed() reports readiness. Pure state.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Boot step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BootStep {
    /// Verify substrate fingerprint.
    FingerprintVerify,
    /// Load attestation chain.
    AttestationLoad,
    /// Canary probe baseline.
    CanaryProbe,
    /// Load rule packs.
    RulePackLoad,
    /// Network baseline probe.
    NetworkBaseline,
    /// Open operator connection.
    AcceptOperatorConnection,
}

/// Per-step status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StepStatus {
    /// Not yet attempted.
    Pending,
    /// Currently running.
    Running,
    /// Passed.
    Passed,
    /// Failed.
    Failed,
    /// Skipped (only allowed for non-required steps).
    Skipped,
}

/// Per-step record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StepRecord {
    /// Step.
    pub step: BootStep,
    /// Status.
    pub status: StepStatus,
    /// Required (Skipped not allowed when true)?
    pub required: bool,
    /// Optional failure reason.
    pub failure_reason: Option<String>,
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubstrateColdBootPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Step records in order.
    pub records: Vec<StepRecord>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BootError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Required step marked Skipped.
    #[error("required step {0:?} cannot be skipped")]
    RequiredSkipped(BootStep),
    /// Duplicate step in records.
    #[error("duplicate step: {0:?}")]
    DuplicateStep(BootStep),
}

impl SubstrateColdBootPolicy {
    /// Canonical: all steps required except NetworkBaseline (optional).
    pub fn canonical() -> Self {
        let rec = |step, required| StepRecord {
            step,
            status: StepStatus::Pending,
            required,
            failure_reason: None,
        };
        Self {
            schema_version: SCHEMA_VERSION.into(),
            records: vec![
                rec(BootStep::FingerprintVerify, true),
                rec(BootStep::AttestationLoad, true),
                rec(BootStep::CanaryProbe, true),
                rec(BootStep::RulePackLoad, true),
                rec(BootStep::NetworkBaseline, false),
                rec(BootStep::AcceptOperatorConnection, true),
            ],
        }
    }

    /// Mark a step's status.
    pub fn set_status(&mut self, step: BootStep, status: StepStatus, reason: Option<String>) {
        if let Some(r) = self.records.iter_mut().find(|r| r.step == step) {
            r.status = status;
            r.failure_reason = reason;
        }
    }

    /// First failed step (Pending/Running not counted; Failed only). None when no failures.
    pub fn first_failure(&self) -> Option<&StepRecord> {
        self.records.iter().find(|r| r.status == StepStatus::Failed)
    }

    /// First step not yet completed (Passed/Skipped). None when all done.
    pub fn next_step(&self) -> Option<&StepRecord> {
        self.records.iter().find(|r| !matches!(r.status, StepStatus::Passed | StepStatus::Skipped))
    }

    /// All required steps passed (or non-required skipped allowed)?
    pub fn all_passed(&self) -> bool {
        self.records.iter().all(|r| match r.status {
            StepStatus::Passed => true,
            StepStatus::Skipped => !r.required,
            _ => false,
        })
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BootError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BootError::SchemaMismatch);
        }
        use std::collections::HashSet;
        let mut seen: HashSet<BootStep> = HashSet::new();
        for r in &self.records {
            if !seen.insert(r.step) { return Err(BootError::DuplicateStep(r.step)); }
            if r.required && r.status == StepStatus::Skipped {
                return Err(BootError::RequiredSkipped(r.step));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        SubstrateColdBootPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn fresh_canonical_not_all_passed() {
        let p = SubstrateColdBootPolicy::canonical();
        assert!(!p.all_passed());
    }

    #[test]
    fn first_failure_after_failure() {
        let mut p = SubstrateColdBootPolicy::canonical();
        p.set_status(BootStep::CanaryProbe, StepStatus::Failed, Some("baseline drift".into()));
        let f = p.first_failure().unwrap();
        assert_eq!(f.step, BootStep::CanaryProbe);
        assert_eq!(f.failure_reason.as_deref(), Some("baseline drift"));
    }

    #[test]
    fn next_step_pending() {
        let p = SubstrateColdBootPolicy::canonical();
        let n = p.next_step().unwrap();
        assert_eq!(n.step, BootStep::FingerprintVerify);
    }

    #[test]
    fn all_passed_when_all_done() {
        let mut p = SubstrateColdBootPolicy::canonical();
        for step in [
            BootStep::FingerprintVerify,
            BootStep::AttestationLoad,
            BootStep::CanaryProbe,
            BootStep::RulePackLoad,
            BootStep::NetworkBaseline,
            BootStep::AcceptOperatorConnection,
        ] {
            p.set_status(step, StepStatus::Passed, None);
        }
        assert!(p.all_passed());
    }

    #[test]
    fn optional_can_skip() {
        let mut p = SubstrateColdBootPolicy::canonical();
        // Skip the only optional step.
        p.set_status(BootStep::NetworkBaseline, StepStatus::Skipped, None);
        // Pass the others.
        for step in [
            BootStep::FingerprintVerify,
            BootStep::AttestationLoad,
            BootStep::CanaryProbe,
            BootStep::RulePackLoad,
            BootStep::AcceptOperatorConnection,
        ] {
            p.set_status(step, StepStatus::Passed, None);
        }
        assert!(p.all_passed());
        p.validate().unwrap();
    }

    #[test]
    fn required_skipped_rejected_on_validate() {
        let mut p = SubstrateColdBootPolicy::canonical();
        p.set_status(BootStep::FingerprintVerify, StepStatus::Skipped, None);
        assert!(matches!(p.validate().unwrap_err(), BootError::RequiredSkipped(_)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = SubstrateColdBootPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), BootError::SchemaMismatch));
    }

    #[test]
    fn step_serde_kebab() {
        assert_eq!(serde_json::to_string(&BootStep::FingerprintVerify).unwrap(), "\"fingerprint-verify\"");
        assert_eq!(serde_json::to_string(&BootStep::AcceptOperatorConnection).unwrap(), "\"accept-operator-connection\"");
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = SubstrateColdBootPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: SubstrateColdBootPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
