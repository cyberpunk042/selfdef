//! `selfdef-emergency-stop-policy` — IPS emergency-stop authority.
//!
//! When the kill switch is engaged the engine refuses every operation
//! except a small whitelist of rescue-class operations: snapshotting
//! state, draining the audit log, and orderly wind-down. The stop
//! state only clears when the operator (or a designated authority)
//! issues an authenticated `release`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Trigger source — who/what engaged the stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StopTrigger {
    /// Operator pressed the kill switch.
    Operator,
    /// Automated guard tripped (resource exhaustion, anomaly).
    Guard,
    /// Watchdog timeout — engine unresponsive.
    Watchdog,
    /// Loss-of-quorum from an external authority.
    QuorumLoss,
    /// Substrate self-test failed catastrophically.
    SelfTestFail,
}

/// Reason class for routing rescue actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationClass {
    /// Snapshot current state to disk.
    Snapshot,
    /// Drain pending audit/event log entries.
    AuditDrain,
    /// Orderly wind-down (close connections, flush buffers).
    WindDown,
    /// Read-only inspection of internal state.
    Inspect,
    /// Regular execution path (always denied when stopped).
    Execute,
    /// Configuration mutation (always denied when stopped).
    Configure,
    /// New session / new plan (always denied when stopped).
    NewWork,
}

/// Decision returned by the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StopGateDecision {
    /// Operation permitted (either not stopped, or rescue-class).
    Allow,
    /// Operation refused while stop is engaged.
    Deny,
}

/// Stop engagement record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StopEngagement {
    /// What tripped the stop.
    pub trigger: StopTrigger,
    /// Human-readable reason (≤ 200 chars).
    pub reason: String,
    /// ISO-8601 UTC engagement time.
    pub engaged_at: String,
    /// Optional id of the operator/authority that engaged it.
    pub by: String,
}

/// Emergency-stop policy envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmergencyStopPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Current engagement (None = not stopped).
    pub engaged: Option<StopEngagement>,
    /// Required release authority id (must match `release.by`).
    pub release_authority: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum StopError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty reason.
    #[error("reason empty")]
    EmptyReason,
    /// Reason exceeds 200 chars.
    #[error("reason length {0} > 200")]
    ReasonTooLong(usize),
    /// Empty `by` operator/authority id.
    #[error("by empty")]
    EmptyBy,
    /// Release attempt while not engaged.
    #[error("not engaged")]
    NotEngaged,
    /// Release `by` did not match `release_authority`.
    #[error("release authority mismatch: expected {expected}, got {got}")]
    AuthorityMismatch {
        /// expected.
        expected: String,
        /// got.
        got: String,
    },
    /// Empty release authority configured.
    #[error("release_authority empty")]
    EmptyAuthority,
}

impl EmergencyStopPolicy {
    /// New policy with a configured release authority. Not engaged.
    pub fn new(release_authority: &str) -> Result<Self, StopError> {
        if release_authority.is_empty() {
            return Err(StopError::EmptyAuthority);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            engaged: None,
            release_authority: release_authority.into(),
        })
    }

    /// Engage the stop. Idempotent — re-engaging replaces the record.
    pub fn engage(
        &mut self,
        trigger: StopTrigger,
        reason: &str,
        engaged_at: &str,
        by: &str,
    ) -> Result<(), StopError> {
        check_engagement_shape(reason, by)?;
        self.engaged = Some(StopEngagement {
            trigger,
            reason: reason.into(),
            engaged_at: engaged_at.into(),
            by: by.into(),
        });
        Ok(())
    }

    /// Release the stop. Requires the caller's `by` to match
    /// `release_authority`.
    pub fn release(&mut self, by: &str) -> Result<(), StopError> {
        if by.is_empty() {
            return Err(StopError::EmptyBy);
        }
        if self.engaged.is_none() {
            return Err(StopError::NotEngaged);
        }
        if by != self.release_authority {
            return Err(StopError::AuthorityMismatch {
                expected: self.release_authority.clone(),
                got: by.into(),
            });
        }
        self.engaged = None;
        Ok(())
    }

    /// Is the stop currently engaged?
    pub fn is_engaged(&self) -> bool {
        self.engaged.is_some()
    }

    /// Gate an operation by class.
    ///
    /// When not engaged → Allow. When engaged → only rescue-class
    /// operations (Snapshot/AuditDrain/WindDown/Inspect) are allowed.
    pub fn gate(&self, op: OperationClass) -> StopGateDecision {
        if !self.is_engaged() {
            return StopGateDecision::Allow;
        }
        match op {
            OperationClass::Snapshot
            | OperationClass::AuditDrain
            | OperationClass::WindDown
            | OperationClass::Inspect => StopGateDecision::Allow,
            OperationClass::Execute | OperationClass::Configure | OperationClass::NewWork => {
                StopGateDecision::Deny
            }
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), StopError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(StopError::SchemaMismatch);
        }
        if self.release_authority.is_empty() {
            return Err(StopError::EmptyAuthority);
        }
        if let Some(e) = &self.engaged {
            check_engagement_shape(&e.reason, &e.by)?;
        }
        Ok(())
    }
}

fn check_engagement_shape(reason: &str, by: &str) -> Result<(), StopError> {
    if reason.is_empty() {
        return Err(StopError::EmptyReason);
    }
    let n = reason.chars().count();
    if n > 200 {
        return Err(StopError::ReasonTooLong(n));
    }
    if by.is_empty() {
        return Err(StopError::EmptyBy);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> EmergencyStopPolicy {
        EmergencyStopPolicy::new("operator-root").unwrap()
    }

    #[test]
    fn empty_authority_rejected() {
        assert!(matches!(
            EmergencyStopPolicy::new("").unwrap_err(),
            StopError::EmptyAuthority
        ));
    }

    #[test]
    fn fresh_policy_allows_everything() {
        let p = p();
        assert!(!p.is_engaged());
        for op in [
            OperationClass::Execute,
            OperationClass::Configure,
            OperationClass::NewWork,
            OperationClass::Snapshot,
            OperationClass::AuditDrain,
            OperationClass::WindDown,
            OperationClass::Inspect,
        ] {
            assert_eq!(p.gate(op), StopGateDecision::Allow);
        }
    }

    #[test]
    fn engaged_denies_execute_configure_newwork() {
        let mut p = p();
        p.engage(
            StopTrigger::Operator,
            "panic",
            "2026-05-19T00:00:00Z",
            "ops-1",
        )
        .unwrap();
        assert!(p.is_engaged());
        assert_eq!(p.gate(OperationClass::Execute), StopGateDecision::Deny);
        assert_eq!(p.gate(OperationClass::Configure), StopGateDecision::Deny);
        assert_eq!(p.gate(OperationClass::NewWork), StopGateDecision::Deny);
    }

    #[test]
    fn engaged_allows_rescue_class() {
        let mut p = p();
        p.engage(StopTrigger::Watchdog, "hang", "2026-05-19T00:00:00Z", "wd")
            .unwrap();
        assert_eq!(p.gate(OperationClass::Snapshot), StopGateDecision::Allow);
        assert_eq!(p.gate(OperationClass::AuditDrain), StopGateDecision::Allow);
        assert_eq!(p.gate(OperationClass::WindDown), StopGateDecision::Allow);
        assert_eq!(p.gate(OperationClass::Inspect), StopGateDecision::Allow);
    }

    #[test]
    fn release_clears_engagement() {
        let mut p = p();
        p.engage(
            StopTrigger::Operator,
            "panic",
            "2026-05-19T00:00:00Z",
            "ops-1",
        )
        .unwrap();
        p.release("operator-root").unwrap();
        assert!(!p.is_engaged());
    }

    #[test]
    fn release_wrong_authority_rejected() {
        let mut p = p();
        p.engage(
            StopTrigger::Operator,
            "panic",
            "2026-05-19T00:00:00Z",
            "ops-1",
        )
        .unwrap();
        assert!(matches!(
            p.release("intruder").unwrap_err(),
            StopError::AuthorityMismatch { .. }
        ));
        assert!(p.is_engaged());
    }

    #[test]
    fn release_when_not_engaged_rejected() {
        let mut p = p();
        assert!(matches!(
            p.release("operator-root").unwrap_err(),
            StopError::NotEngaged
        ));
    }

    #[test]
    fn empty_reason_rejected() {
        let mut p = p();
        assert!(matches!(
            p.engage(StopTrigger::Operator, "", "t", "by").unwrap_err(),
            StopError::EmptyReason
        ));
    }

    #[test]
    fn reason_too_long_rejected() {
        let mut p = p();
        let long = "x".repeat(201);
        assert!(matches!(
            p.engage(StopTrigger::Operator, &long, "t", "by")
                .unwrap_err(),
            StopError::ReasonTooLong(201)
        ));
    }

    #[test]
    fn empty_by_rejected_on_engage() {
        let mut p = p();
        assert!(matches!(
            p.engage(StopTrigger::Operator, "r", "t", "").unwrap_err(),
            StopError::EmptyBy
        ));
    }

    #[test]
    fn re_engage_overwrites() {
        let mut p = p();
        p.engage(StopTrigger::Operator, "first", "t1", "ops")
            .unwrap();
        p.engage(StopTrigger::Guard, "second", "t2", "guard")
            .unwrap();
        let e = p.engaged.as_ref().unwrap();
        assert_eq!(e.trigger, StopTrigger::Guard);
        assert_eq!(e.reason, "second");
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = p();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            StopError::SchemaMismatch
        ));
    }

    #[test]
    fn trigger_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&StopTrigger::Operator).unwrap(),
            "\"operator\""
        );
        assert_eq!(
            serde_json::to_string(&StopTrigger::QuorumLoss).unwrap(),
            "\"quorum-loss\""
        );
        assert_eq!(
            serde_json::to_string(&StopTrigger::SelfTestFail).unwrap(),
            "\"self-test-fail\""
        );
    }

    #[test]
    fn op_class_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&OperationClass::AuditDrain).unwrap(),
            "\"audit-drain\""
        );
        assert_eq!(
            serde_json::to_string(&OperationClass::WindDown).unwrap(),
            "\"wind-down\""
        );
        assert_eq!(
            serde_json::to_string(&OperationClass::NewWork).unwrap(),
            "\"new-work\""
        );
    }

    #[test]
    fn policy_serde_roundtrip() {
        let mut p = p();
        p.engage(
            StopTrigger::Operator,
            "panic",
            "2026-05-19T00:00:00Z",
            "ops-1",
        )
        .unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: EmergencyStopPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
