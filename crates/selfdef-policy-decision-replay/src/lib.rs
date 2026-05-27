//! `selfdef-policy-decision-replay` — replay a captured decision.
//!
//! Compares a captured `PolicyDecision` against a freshly-computed one
//! for the same inputs. Returns `ReplayResult`:
//! - `Identical`: outcomes + risk + side-effect all match
//! - `Drift`: same outcome but a non-outcome field changed
//! - `Refused`: outcome itself differs
//!
//! This crate doesn't compute the live decision — the caller passes
//! both. Selfdef uses this for postmortem analysis + replay-mode tests.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_policy_decision::{Outcome, PolicyDecision};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Replay outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReplayResult {
    /// Identical (full match).
    Identical,
    /// Same outcome, different sub-field(s).
    Drift,
    /// Different outcome.
    Refused,
}

/// Replay report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayReport {
    /// Schema version.
    pub schema_version: String,
    /// Captured trace_id.
    pub trace_id: String,
    /// Captured outcome.
    pub captured_outcome: Outcome,
    /// Live outcome.
    pub live_outcome: Outcome,
    /// Result classification.
    pub result: ReplayResult,
    /// Drifted field names (empty when Identical or Refused).
    pub drifted_fields: Vec<String>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ReplayError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Trace_ids don't match between captured and live.
    #[error("trace_id mismatch: captured={captured}, live={live}")]
    TraceIdMismatch {
        /// captured.
        captured: String,
        /// live.
        live: String,
    },
}

/// Compare captured vs live decision.
pub fn compare(
    captured: &PolicyDecision,
    live: &PolicyDecision,
) -> Result<ReplayReport, ReplayError> {
    if captured.trace_id != live.trace_id {
        return Err(ReplayError::TraceIdMismatch {
            captured: captured.trace_id.clone(),
            live: live.trace_id.clone(),
        });
    }

    if captured.outcome != live.outcome {
        return Ok(ReplayReport {
            schema_version: SCHEMA_VERSION.into(),
            trace_id: captured.trace_id.clone(),
            captured_outcome: captured.outcome,
            live_outcome: live.outcome,
            result: ReplayResult::Refused,
            drifted_fields: Vec::new(),
        });
    }

    let mut drifted = Vec::new();
    if captured.risk != live.risk {
        drifted.push("risk".into());
    }
    if captured.side_effect_class != live.side_effect_class {
        drifted.push("side_effect_class".into());
    }
    if captured.context_sensitivity != live.context_sensitivity {
        drifted.push("context_sensitivity".into());
    }
    if captured.user_approval != live.user_approval {
        drifted.push("user_approval".into());
    }
    if captured.profile != live.profile {
        drifted.push("profile".into());
    }
    if captured.model_provider != live.model_provider {
        drifted.push("model_provider".into());
    }
    if captured.reason != live.reason {
        drifted.push("reason".into());
    }
    if captured.signature != live.signature {
        drifted.push("signature".into());
    }

    let result = if drifted.is_empty() {
        ReplayResult::Identical
    } else {
        ReplayResult::Drift
    };
    Ok(ReplayReport {
        schema_version: SCHEMA_VERSION.into(),
        trace_id: captured.trace_id.clone(),
        captured_outcome: captured.outcome,
        live_outcome: live.outcome,
        result,
        drifted_fields: drifted,
    })
}

impl ReplayReport {
    /// Validate.
    pub fn validate(&self) -> Result<(), ReplayError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ReplayError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_policy_decision::{
        ContextSensitivity, RiskClass, SideEffectClass, UserApprovalState,
    };

    fn d(outcome: Outcome, risk: RiskClass) -> PolicyDecision {
        PolicyDecision {
            schema_version: "1.0.0".into(),
            subject: "alice".into(),
            action: "fs.write".into(),
            resource: "/x".into(),
            intent: "ship".into(),
            profile: "careful".into(),
            risk,
            model_provider: "local:rocm-3090".into(),
            context_sensitivity: ContextSensitivity::Internal,
            side_effect_class: SideEffectClass::FsWrite,
            user_approval: UserApprovalState::NotRequired,
            outcome,
            reason: "ok".into(),
            trace_id: "tr-1".into(),
            signature: "sig".into(),
        }
    }

    #[test]
    fn identical_match() {
        let a = d(Outcome::Allow, RiskClass::Low);
        let b = d(Outcome::Allow, RiskClass::Low);
        let r = compare(&a, &b).unwrap();
        assert_eq!(r.result, ReplayResult::Identical);
        assert!(r.drifted_fields.is_empty());
    }

    #[test]
    fn refused_when_outcome_differs() {
        let a = d(Outcome::Allow, RiskClass::Low);
        let b = d(Outcome::Deny, RiskClass::Low);
        let r = compare(&a, &b).unwrap();
        assert_eq!(r.result, ReplayResult::Refused);
    }

    #[test]
    fn drift_when_only_risk_differs() {
        let a = d(Outcome::Allow, RiskClass::Low);
        let b = d(Outcome::Allow, RiskClass::High);
        let r = compare(&a, &b).unwrap();
        assert_eq!(r.result, ReplayResult::Drift);
        assert_eq!(r.drifted_fields, vec!["risk"]);
    }

    #[test]
    fn drift_lists_multiple_fields() {
        let a = d(Outcome::Allow, RiskClass::Low);
        let mut b = d(Outcome::Allow, RiskClass::High);
        b.reason = "different".into();
        b.signature = "other".into();
        let r = compare(&a, &b).unwrap();
        assert_eq!(r.result, ReplayResult::Drift);
        assert!(r.drifted_fields.contains(&"risk".to_string()));
        assert!(r.drifted_fields.contains(&"reason".to_string()));
        assert!(r.drifted_fields.contains(&"signature".to_string()));
    }

    #[test]
    fn trace_id_mismatch_rejected() {
        let a = d(Outcome::Allow, RiskClass::Low);
        let mut b = d(Outcome::Allow, RiskClass::Low);
        b.trace_id = "tr-2".into();
        assert!(matches!(
            compare(&a, &b).unwrap_err(),
            ReplayError::TraceIdMismatch { .. }
        ));
    }

    #[test]
    fn result_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&ReplayResult::Identical).unwrap(),
            "\"identical\""
        );
        assert_eq!(
            serde_json::to_string(&ReplayResult::Drift).unwrap(),
            "\"drift\""
        );
        assert_eq!(
            serde_json::to_string(&ReplayResult::Refused).unwrap(),
            "\"refused\""
        );
    }

    #[test]
    fn report_serde_roundtrip() {
        let a = d(Outcome::Allow, RiskClass::Low);
        let b = d(Outcome::Allow, RiskClass::High);
        let r = compare(&a, &b).unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: ReplayReport = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
