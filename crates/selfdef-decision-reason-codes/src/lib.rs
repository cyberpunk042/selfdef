//! `selfdef-decision-reason-codes` — canonical reason-code taxonomy.
//!
//! Every policy-gate that issues a non-Allow decision MUST reference
//! one of these `ReasonCode`s. The cockpit, audit log, and replay
//! engine all index by this key so operator-facing messages stay
//! consistent regardless of which gate triggered.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Canonical reason code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReasonCode {
    /// TopSecret payload tried to egress.
    TopSecretEgress,
    /// Confidential payload to external destination.
    ConfidentialExternalEgress,
    /// Operator declined an Ask.
    OperatorDeclined,
    /// Required operator approval missing.
    ApprovalRequired,
    /// Per-class quota exhausted.
    QuotaExhausted,
    /// Outside operator-configured time window.
    NotWithinTimeWindow,
    /// Cross-kind / cross-class violation.
    CrossClassViolation,
    /// Sandbox tier insufficient.
    SandboxTierInsufficient,
    /// Trust tier insufficient for autonomous exec.
    TrustTierInsufficient,
    /// Prompt-injection signal detected.
    PromptInjectionDetected,
    /// Emergency stop engaged.
    EmergencyStopEngaged,
    /// Schema drift / version mismatch.
    SchemaDrift,
    /// Substrate attestation chain broken.
    AttestationBroken,
    /// Tool version not pinned / mismatch.
    ToolVersionMismatch,
    /// DNS egress denied (deny / never).
    DnsEgressDenied,
    /// Process launch denied.
    ProcessLaunchDenied,
    /// FS watch denied.
    FsWatchDenied,
    /// Canary tripwire fired.
    CanaryTripwireFired,
    /// Replay divergence detected.
    ReplayDivergence,
    /// Generic operator policy (catch-all; never preferred).
    PolicyOther,
}

impl ReasonCode {
    /// Stable kebab-case string (matches serde repr).
    pub fn key(self) -> &'static str {
        match self {
            ReasonCode::TopSecretEgress => "top-secret-egress",
            ReasonCode::ConfidentialExternalEgress => "confidential-external-egress",
            ReasonCode::OperatorDeclined => "operator-declined",
            ReasonCode::ApprovalRequired => "approval-required",
            ReasonCode::QuotaExhausted => "quota-exhausted",
            ReasonCode::NotWithinTimeWindow => "not-within-time-window",
            ReasonCode::CrossClassViolation => "cross-class-violation",
            ReasonCode::SandboxTierInsufficient => "sandbox-tier-insufficient",
            ReasonCode::TrustTierInsufficient => "trust-tier-insufficient",
            ReasonCode::PromptInjectionDetected => "prompt-injection-detected",
            ReasonCode::EmergencyStopEngaged => "emergency-stop-engaged",
            ReasonCode::SchemaDrift => "schema-drift",
            ReasonCode::AttestationBroken => "attestation-broken",
            ReasonCode::ToolVersionMismatch => "tool-version-mismatch",
            ReasonCode::DnsEgressDenied => "dns-egress-denied",
            ReasonCode::ProcessLaunchDenied => "process-launch-denied",
            ReasonCode::FsWatchDenied => "fs-watch-denied",
            ReasonCode::CanaryTripwireFired => "canary-tripwire-fired",
            ReasonCode::ReplayDivergence => "replay-divergence",
            ReasonCode::PolicyOther => "policy-other",
        }
    }

    /// Default operator-facing message.
    pub fn default_message(self) -> &'static str {
        match self {
            ReasonCode::TopSecretEgress => "Top-Secret content may not leave the engine.",
            ReasonCode::ConfidentialExternalEgress => "Confidential content cannot reach external destinations.",
            ReasonCode::OperatorDeclined => "The operator declined this action.",
            ReasonCode::ApprovalRequired => "Operator approval is required for this action.",
            ReasonCode::QuotaExhausted => "Per-class quota exhausted; try again later.",
            ReasonCode::NotWithinTimeWindow => "Outside the configured time window for this operation.",
            ReasonCode::CrossClassViolation => "Action violates a cross-class boundary.",
            ReasonCode::SandboxTierInsufficient => "Sandbox tier insufficient for this operation.",
            ReasonCode::TrustTierInsufficient => "LLM output's trust tier is insufficient for autonomous execution.",
            ReasonCode::PromptInjectionDetected => "Prompt-injection pattern detected in input.",
            ReasonCode::EmergencyStopEngaged => "Emergency stop is engaged; only rescue-class operations are permitted.",
            ReasonCode::SchemaDrift => "A schema-version mismatch was detected.",
            ReasonCode::AttestationBroken => "Substrate attestation chain is broken.",
            ReasonCode::ToolVersionMismatch => "Tool version does not match the configured pin.",
            ReasonCode::DnsEgressDenied => "DNS egress denied for this hostname.",
            ReasonCode::ProcessLaunchDenied => "Process spawn denied under current policy.",
            ReasonCode::FsWatchDenied => "Filesystem watch path is not permitted.",
            ReasonCode::CanaryTripwireFired => "A canary tripwire fired.",
            ReasonCode::ReplayDivergence => "Replay diverged from the recorded transcript.",
            ReasonCode::PolicyOther => "Action denied by policy.",
        }
    }

    /// All variants in declaration order.
    pub fn all() -> &'static [ReasonCode] {
        const ALL: [ReasonCode; 20] = [
            ReasonCode::TopSecretEgress,
            ReasonCode::ConfidentialExternalEgress,
            ReasonCode::OperatorDeclined,
            ReasonCode::ApprovalRequired,
            ReasonCode::QuotaExhausted,
            ReasonCode::NotWithinTimeWindow,
            ReasonCode::CrossClassViolation,
            ReasonCode::SandboxTierInsufficient,
            ReasonCode::TrustTierInsufficient,
            ReasonCode::PromptInjectionDetected,
            ReasonCode::EmergencyStopEngaged,
            ReasonCode::SchemaDrift,
            ReasonCode::AttestationBroken,
            ReasonCode::ToolVersionMismatch,
            ReasonCode::DnsEgressDenied,
            ReasonCode::ProcessLaunchDenied,
            ReasonCode::FsWatchDenied,
            ReasonCode::CanaryTripwireFired,
            ReasonCode::ReplayDivergence,
            ReasonCode::PolicyOther,
        ];
        &ALL
    }
}

/// A single decision attribution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReasonAttribution {
    /// Schema version.
    pub schema_version: String,
    /// Code.
    pub code: ReasonCode,
    /// Free-form operator-facing detail (≤ 200 chars).
    pub detail: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ReasonError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Detail too long.
    #[error("detail length {0} > 200")]
    DetailTooLong(usize),
}

impl ReasonAttribution {
    /// Build.
    pub fn new(code: ReasonCode, detail: &str) -> Result<Self, ReasonError> {
        let n = detail.chars().count();
        if n > 200 {
            return Err(ReasonError::DetailTooLong(n));
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            code,
            detail: detail.into(),
        })
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ReasonError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ReasonError::SchemaMismatch);
        }
        let n = self.detail.chars().count();
        if n > 200 {
            return Err(ReasonError::DetailTooLong(n));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_returns_20_variants() {
        assert_eq!(ReasonCode::all().len(), 20);
    }

    #[test]
    fn key_matches_serde() {
        let r = ReasonCode::TopSecretEgress;
        let serde_repr = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_repr, format!("\"{}\"", r.key()));
    }

    #[test]
    fn all_keys_unique() {
        use std::collections::HashSet;
        let mut s: HashSet<&str> = HashSet::new();
        for c in ReasonCode::all() {
            assert!(s.insert(c.key()), "duplicate key: {}", c.key());
        }
    }

    #[test]
    fn default_messages_nonempty() {
        for c in ReasonCode::all() {
            assert!(!c.default_message().is_empty());
        }
    }

    #[test]
    fn new_detail_under_200() {
        let r = ReasonAttribution::new(ReasonCode::QuotaExhausted, "9/10 used").unwrap();
        assert_eq!(r.code, ReasonCode::QuotaExhausted);
    }

    #[test]
    fn new_detail_too_long_rejected() {
        let s = "x".repeat(201);
        assert!(matches!(
            ReasonAttribution::new(ReasonCode::PolicyOther, &s).unwrap_err(),
            ReasonError::DetailTooLong(201)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = ReasonAttribution::new(ReasonCode::SchemaDrift, "").unwrap();
        r.schema_version = "9.9.9".into();
        assert!(matches!(r.validate().unwrap_err(), ReasonError::SchemaMismatch));
    }

    #[test]
    fn code_serde_kebab() {
        assert_eq!(serde_json::to_string(&ReasonCode::EmergencyStopEngaged).unwrap(), "\"emergency-stop-engaged\"");
        assert_eq!(serde_json::to_string(&ReasonCode::TrustTierInsufficient).unwrap(), "\"trust-tier-insufficient\"");
    }

    #[test]
    fn attribution_serde_roundtrip() {
        let r = ReasonAttribution::new(ReasonCode::OperatorDeclined, "user clicked cancel").unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: ReasonAttribution = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
