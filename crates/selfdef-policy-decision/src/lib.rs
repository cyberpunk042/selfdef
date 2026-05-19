//! `selfdef-policy-decision` — MS033 10-field policy decision object.
//!
//! Per MS033 + E0336 + F03863-F03872 + R07703-R07712 + dump 16220:
//!
//! The decision object is the canonical wire surface every action
//! observes; matches sovereign-os M049 Intent-Based Policy 10-field
//! input. Every action MUST carry one of 4 outcomes (allow/deny/ask/
//! sandbox) per F03947.
//!
//! Doctrines preserved verbatim:
//!
//! > "Every action becomes observable and governed" (F03842 dump 16216)
//!
//! > "Trace is emitted when the action is decided, not after" (F03942 dump 16221)
//!
//! > "Every action MUST have a policy decision object" (F03943 dump 16220)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Doctrine surface verbatim per F03842 dump 16216.
pub const DOCTRINE_EVERY_ACTION_OBSERVABLE: &str =
    "Every action becomes observable and governed";

/// Doctrine surface verbatim per F03942 dump 16221.
pub const DOCTRINE_TRACE_AT_DECISION: &str =
    "Trace is emitted when the action is decided, not after";

/// 4-outcome state per F03947 + R07731-R07734.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    /// Allow — action proceeds.
    Allow,
    /// Deny — action blocked.
    Deny,
    /// Ask — operator approval queued (D-06).
    Ask,
    /// Sandbox — escalate to MS036 tier sandbox.
    Sandbox,
}

/// Risk class (axis-bounded; F03868).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskClass {
    /// Negligible — observe-only path.
    Negligible,
    /// Low — bounded side effect.
    Low,
    /// Medium — durable change.
    Medium,
    /// High — multi-system change.
    High,
    /// Critical — sovereignty / safety boundary.
    Critical,
}

/// Side-effect class per F03871.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SideEffectClass {
    /// No side effects.
    None,
    /// Read-only.
    ReadOnly,
    /// Filesystem write within workspace.
    FsWrite,
    /// Network egress.
    NetworkEgress,
    /// Process spawn / kill.
    Process,
    /// Persistent change (ZFS commit / kernel param / etc.).
    Persistent,
}

/// User approval state per F03872.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UserApprovalState {
    /// Not required.
    NotRequired,
    /// Required + pending.
    PendingRequired,
    /// Operator-approved (MS003-signed).
    Approved,
    /// Operator-rejected.
    Rejected,
}

/// Context-sensitivity tag per F03870.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContextSensitivity {
    /// Public (no secrets touched).
    Public,
    /// Internal (operator-owned but not secret).
    Internal,
    /// Confidential (secrets / keys / personal data).
    Confidential,
}

/// 10-field policy decision object per dump 16220 + R07703-R07712.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDecision {
    /// Schema version.
    pub schema_version: String,
    /// Field 1 — subject (actor MS003 fingerprint) per F03863.
    pub subject: String,
    /// Field 2 — action (canonical verb) per F03864.
    pub action: String,
    /// Field 3 — resource (target path / domain / capability) per F03865.
    pub resource: String,
    /// Field 4 — intent (free-form operator-readable) per F03866.
    pub intent: String,
    /// Field 5 — profile (MS040 name) per F03867.
    pub profile: String,
    /// Field 6 — risk class per F03868.
    pub risk: RiskClass,
    /// Field 7 — model / provider that originated the action per F03869.
    pub model_provider: String,
    /// Field 8 — context sensitivity per F03870.
    pub context_sensitivity: ContextSensitivity,
    /// Field 9 — side effect class per F03871.
    pub side_effect_class: SideEffectClass,
    /// Field 10 — user approval state per F03872.
    pub user_approval: UserApprovalState,
    /// Decision outcome (F03947).
    pub outcome: Outcome,
    /// Reason text (operator-readable).
    pub reason: String,
    /// M049 trace_id (decision-emitted, not after-the-fact per F03942).
    pub trace_id: String,
    /// MS003 signature over canonical-JSON encoding.
    pub signature: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// Schema drift.
    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected.
        expected: String,
        /// Observed.
        actual: String,
    },
    /// One of the 10 mandatory fields is empty.
    #[error("policy decision mandatory field empty: {0}")]
    MandatoryFieldEmpty(&'static str),
    /// Decision was Allow but risk was Critical without approval — refused.
    #[error("Allow on Critical risk requires user_approval=Approved")]
    CriticalAllowWithoutApproval,
    /// Decision was Allow but side effect was Persistent and user_approval missing.
    #[error("Allow on Persistent side-effect requires user_approval=Approved")]
    PersistentAllowWithoutApproval,
    /// Decision was Ask but no trace_id (Ask must still emit trace per F03942).
    #[error("Ask outcome must emit trace_id (F03942)")]
    AskWithoutTrace,
    /// Decision missing signature (every decision MS003-signed).
    #[error("policy decision unsigned (every decision must be MS003-signed)")]
    DecisionUnsigned,
}

impl PolicyDecision {
    /// Validate all invariants:
    /// - schema version
    /// - 10 mandatory fields non-empty
    /// - critical-risk Allow requires approval
    /// - persistent side-effect Allow requires approval
    /// - all decisions emit trace_id
    /// - signature present
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(PolicyError::SchemaMismatch {
                expected: SCHEMA_VERSION.into(),
                actual: self.schema_version.clone(),
            });
        }
        if self.signature.is_empty() {
            return Err(PolicyError::DecisionUnsigned);
        }
        // 10 fields — strings non-empty (enums always set, so skip).
        if self.subject.is_empty() { return Err(PolicyError::MandatoryFieldEmpty("subject")); }
        if self.action.is_empty() { return Err(PolicyError::MandatoryFieldEmpty("action")); }
        if self.resource.is_empty() { return Err(PolicyError::MandatoryFieldEmpty("resource")); }
        if self.intent.is_empty() { return Err(PolicyError::MandatoryFieldEmpty("intent")); }
        if self.profile.is_empty() { return Err(PolicyError::MandatoryFieldEmpty("profile")); }
        if self.model_provider.is_empty() { return Err(PolicyError::MandatoryFieldEmpty("model_provider")); }
        if self.trace_id.is_empty() { return Err(PolicyError::AskWithoutTrace); }

        // Critical-risk Allow rule.
        if self.outcome == Outcome::Allow
            && self.risk == RiskClass::Critical
            && self.user_approval != UserApprovalState::Approved
        {
            return Err(PolicyError::CriticalAllowWithoutApproval);
        }
        // Persistent side-effect Allow rule.
        if self.outcome == Outcome::Allow
            && self.side_effect_class == SideEffectClass::Persistent
            && self.user_approval != UserApprovalState::Approved
        {
            return Err(PolicyError::PersistentAllowWithoutApproval);
        }
        Ok(())
    }

    /// Whether the action proceeds based on outcome.
    pub fn proceeds(&self) -> bool {
        self.outcome == Outcome::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_decision() -> PolicyDecision {
        PolicyDecision {
            schema_version: SCHEMA_VERSION.into(),
            subject: "operator-fp".into(),
            action: "fs.write".into(),
            resource: "/workspace/x.rs".into(),
            intent: "ship new feature".into(),
            profile: "careful".into(),
            risk: RiskClass::Low,
            model_provider: "local:rocm-3090".into(),
            context_sensitivity: ContextSensitivity::Internal,
            side_effect_class: SideEffectClass::FsWrite,
            user_approval: UserApprovalState::NotRequired,
            outcome: Outcome::Allow,
            reason: "policy bus matched grant".into(),
            trace_id: "trace-001".into(),
            signature: "ms003-sig".into(),
        }
    }

    // --- 10-field validation ---

    #[test]
    fn ok_decision_validates() {
        ok_decision().validate().unwrap();
    }

    #[test]
    fn empty_subject_rejected() {
        let mut d = ok_decision();
        d.subject = String::new();
        assert!(matches!(d.validate().unwrap_err(), PolicyError::MandatoryFieldEmpty("subject")));
    }

    #[test]
    fn empty_action_rejected() {
        let mut d = ok_decision();
        d.action = String::new();
        assert!(matches!(d.validate().unwrap_err(), PolicyError::MandatoryFieldEmpty("action")));
    }

    #[test]
    fn empty_resource_rejected() {
        let mut d = ok_decision();
        d.resource = String::new();
        assert!(matches!(d.validate().unwrap_err(), PolicyError::MandatoryFieldEmpty("resource")));
    }

    #[test]
    fn empty_intent_rejected() {
        let mut d = ok_decision();
        d.intent = String::new();
        assert!(matches!(d.validate().unwrap_err(), PolicyError::MandatoryFieldEmpty("intent")));
    }

    #[test]
    fn empty_profile_rejected() {
        let mut d = ok_decision();
        d.profile = String::new();
        assert!(matches!(d.validate().unwrap_err(), PolicyError::MandatoryFieldEmpty("profile")));
    }

    #[test]
    fn empty_model_provider_rejected() {
        let mut d = ok_decision();
        d.model_provider = String::new();
        assert!(matches!(d.validate().unwrap_err(), PolicyError::MandatoryFieldEmpty("model_provider")));
    }

    #[test]
    fn empty_trace_id_rejected() {
        let mut d = ok_decision();
        d.trace_id = String::new();
        assert!(matches!(d.validate().unwrap_err(), PolicyError::AskWithoutTrace));
    }

    #[test]
    fn empty_signature_rejected() {
        let mut d = ok_decision();
        d.signature = String::new();
        assert!(matches!(d.validate().unwrap_err(), PolicyError::DecisionUnsigned));
    }

    // --- Critical-risk + Persistent rules ---

    #[test]
    fn critical_allow_without_approval_rejected() {
        let mut d = ok_decision();
        d.risk = RiskClass::Critical;
        d.user_approval = UserApprovalState::NotRequired;
        d.outcome = Outcome::Allow;
        assert!(matches!(d.validate().unwrap_err(), PolicyError::CriticalAllowWithoutApproval));
    }

    #[test]
    fn critical_allow_with_approval_accepted() {
        let mut d = ok_decision();
        d.risk = RiskClass::Critical;
        d.user_approval = UserApprovalState::Approved;
        d.outcome = Outcome::Allow;
        d.validate().unwrap();
    }

    #[test]
    fn critical_deny_without_approval_accepted() {
        // Deny is fine on critical risk
        let mut d = ok_decision();
        d.risk = RiskClass::Critical;
        d.outcome = Outcome::Deny;
        d.validate().unwrap();
    }

    #[test]
    fn persistent_allow_without_approval_rejected() {
        let mut d = ok_decision();
        d.side_effect_class = SideEffectClass::Persistent;
        d.outcome = Outcome::Allow;
        d.user_approval = UserApprovalState::NotRequired;
        assert!(matches!(d.validate().unwrap_err(), PolicyError::PersistentAllowWithoutApproval));
    }

    #[test]
    fn persistent_allow_with_approval_accepted() {
        let mut d = ok_decision();
        d.side_effect_class = SideEffectClass::Persistent;
        d.outcome = Outcome::Allow;
        d.user_approval = UserApprovalState::Approved;
        d.validate().unwrap();
    }

    // --- Schema + outcome ---

    #[test]
    fn schema_drift_rejected() {
        let mut d = ok_decision();
        d.schema_version = "9.9.9".into();
        assert!(matches!(d.validate().unwrap_err(), PolicyError::SchemaMismatch { .. }));
    }

    #[test]
    fn proceeds_only_when_allow() {
        let mut d = ok_decision();
        assert!(d.proceeds());
        d.outcome = Outcome::Deny;
        assert!(!d.proceeds());
        d.outcome = Outcome::Ask;
        assert!(!d.proceeds());
        d.outcome = Outcome::Sandbox;
        assert!(!d.proceeds());
    }

    // --- Doctrines ---

    #[test]
    fn doctrine_every_action_verbatim() {
        assert_eq!(DOCTRINE_EVERY_ACTION_OBSERVABLE, "Every action becomes observable and governed");
    }

    #[test]
    fn doctrine_trace_at_decision_verbatim() {
        assert_eq!(DOCTRINE_TRACE_AT_DECISION, "Trace is emitted when the action is decided, not after");
    }

    // --- Serde ---

    #[test]
    fn outcome_serde_kebab() {
        for (o, s) in [
            (Outcome::Allow, "\"allow\""), (Outcome::Deny, "\"deny\""),
            (Outcome::Ask, "\"ask\""), (Outcome::Sandbox, "\"sandbox\""),
        ] {
            assert_eq!(serde_json::to_string(&o).unwrap(), s);
        }
    }

    #[test]
    fn risk_class_serde_kebab() {
        assert_eq!(serde_json::to_string(&RiskClass::Critical).unwrap(), "\"critical\"");
        assert_eq!(serde_json::to_string(&RiskClass::Negligible).unwrap(), "\"negligible\"");
    }

    #[test]
    fn side_effect_class_serde_kebab() {
        assert_eq!(serde_json::to_string(&SideEffectClass::Persistent).unwrap(), "\"persistent\"");
        assert_eq!(serde_json::to_string(&SideEffectClass::NetworkEgress).unwrap(), "\"network-egress\"");
    }

    #[test]
    fn risk_ordering() {
        assert!(RiskClass::Negligible < RiskClass::Low);
        assert!(RiskClass::Low < RiskClass::Medium);
        assert!(RiskClass::Medium < RiskClass::High);
        assert!(RiskClass::High < RiskClass::Critical);
    }

    #[test]
    fn decision_serde_roundtrip() {
        let d = ok_decision();
        let j = serde_json::to_string(&d).unwrap();
        let back: PolicyDecision = serde_json::from_str(&j).unwrap();
        assert_eq!(d, back);
    }
}
