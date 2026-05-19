//! `selfdef-state-snapshot` — unified IPS state envelope.
//!
//! Per the operator standing direction "Continuity is preserving the
//! chain from intent to action to consequence to learning" (sovereign-os
//! M049 KEY LINE), every commit must produce a re-loadable snapshot of
//! the IPS authority state.
//!
//! This crate composes the typed surfaces from:
//! - selfdef-profile-authority-gate (active Profile + per-profile envelope)
//! - selfdef-actor-registry (operator + actor fingerprints)
//! - selfdef-capability-word (issued token bytes)
//! - selfdef-policy-decision (last decision per slot)
//! - selfdef-trace-span (last span chain head)
//! - selfdef-network-boundary (5-profile policy bits)
//!
//! into one signed snapshot persisted to `/var/lib/selfdef/state-snapshot.json`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_actor_registry::ActorRegistry;
use selfdef_capability_word::CapabilityWord;
use selfdef_network_boundary::NetworkProfile;
use selfdef_policy_decision::PolicyDecision;
use selfdef_profile_authority_gate::Profile;
use selfdef_trace_span::TraceSpan;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Canonical on-disk path.
pub const SNAPSHOT_PATH: &str = "/var/lib/selfdef/state-snapshot.json";

/// Unified snapshot envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateSnapshot {
    /// Wire-stable schema version.
    pub schema_version: String,
    /// ISO-8601 UTC capture timestamp.
    pub captured_at: String,
    /// Active profile at snapshot time.
    pub active_profile: Profile,
    /// Active network profile.
    pub active_network_profile: NetworkProfile,
    /// Actor registry.
    pub actor_registry: ActorRegistry,
    /// Currently active capability_word (hex).
    pub active_capability_word_hex: String,
    /// Last applied policy decision.
    pub last_policy_decision: Option<PolicyDecision>,
    /// Tail of recent trace spans (bounded by publisher).
    pub recent_spans: Vec<TraceSpan>,
    /// MS003 envelope signature.
    pub envelope_signature: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SnapshotError {
    /// Schema drift.
    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected.
        expected: String,
        /// Observed.
        actual: String,
    },
    /// Captured_at empty.
    #[error("captured_at empty")]
    CapturedAtMissing,
    /// Envelope signature missing.
    #[error("envelope signature missing (MS003 sign required)")]
    EnvelopeUnsigned,
    /// Capability_word hex parse failed.
    #[error("active_capability_word_hex parse failed: {0}")]
    CapabilityWordInvalid(String),
    /// Embedded actor registry invalid.
    #[error("embedded actor registry invalid: {0}")]
    ActorRegistryInvalid(String),
    /// Embedded recent_spans invalid.
    #[error("embedded recent_spans invalid: {0}")]
    SpansInvalid(String),
    /// Embedded last_policy_decision invalid.
    #[error("embedded policy_decision invalid: {0}")]
    PolicyDecisionInvalid(String),
}

impl StateSnapshot {
    /// Validate composite invariants — top-level + embedded sub-schemas.
    pub fn validate(&self) -> Result<(), SnapshotError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SnapshotError::SchemaMismatch {
                expected: SCHEMA_VERSION.into(),
                actual: self.schema_version.clone(),
            });
        }
        if self.captured_at.is_empty() {
            return Err(SnapshotError::CapturedAtMissing);
        }
        if self.envelope_signature.is_empty() {
            return Err(SnapshotError::EnvelopeUnsigned);
        }
        // Capability word parse.
        CapabilityWord::from_hex(&self.active_capability_word_hex)
            .ok_or_else(|| SnapshotError::CapabilityWordInvalid(self.active_capability_word_hex.clone()))?;
        // Actor registry sub-validation.
        self.actor_registry.validate()
            .map_err(|e| SnapshotError::ActorRegistryInvalid(e.to_string()))?;
        // Each span sub-validation.
        for span in &self.recent_spans {
            selfdef_trace_span::validate(span)
                .map_err(|e| SnapshotError::SpansInvalid(e.to_string()))?;
        }
        // Optional policy-decision sub-validation.
        if let Some(d) = &self.last_policy_decision {
            d.validate()
                .map_err(|e| SnapshotError::PolicyDecisionInvalid(e.to_string()))?;
        }
        Ok(())
    }

    /// Canonical path constant.
    pub fn canonical_path() -> &'static str { SNAPSHOT_PATH }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_actor_registry::{ActorEntry, ActorKind};
    use selfdef_policy_decision::{
        ContextSensitivity, Outcome, RiskClass, SideEffectClass, UserApprovalState,
    };
    use selfdef_trace_span::{HardwareTarget, PolicyResult};

    fn fp32() -> String { "A".repeat(32) }

    fn ok_registry() -> ActorRegistry {
        let mut r = ActorRegistry::default();
        r.signature = "ms003".into();
        r.insert(ActorEntry {
            fingerprint: fp32(),
            name: "op".into(),
            kind: ActorKind::Operator,
            registered_at: "2026-05-19T00:00:00Z".into(),
            revoked_at: String::new(),
            notes: String::new(),
        }).unwrap();
        r
    }

    fn ok_span() -> TraceSpan {
        TraceSpan {
            schema_version: "1.0.0".into(),
            trace_id: "trace-1".into(),
            profile: "careful".into(),
            model: "claude-opus".into(),
            provider: "cloud-anthropic".into(),
            hardware: HardwareTarget::BlackwellOracle,
            tokens_prompt: 100, tokens_completion: 50,
            latency_ms: 800, cost_millicents: 100, risk_score: 10,
            memory_refs: vec![], tool_refs: vec![],
            policy_result: PolicyResult::Allow,
            branch_id: "branch-main".into(),
            signature: "ms003".into(),
            closed_at: "2026-05-19T03:00:00Z".into(),
        }
    }

    fn ok_policy() -> PolicyDecision {
        PolicyDecision {
            schema_version: "1.0.0".into(),
            subject: "op".into(), action: "fs.write".into(),
            resource: "/workspace/x".into(), intent: "ship".into(),
            profile: "careful".into(), risk: RiskClass::Low,
            model_provider: "local:rocm-3090".into(),
            context_sensitivity: ContextSensitivity::Internal,
            side_effect_class: SideEffectClass::FsWrite,
            user_approval: UserApprovalState::NotRequired,
            outcome: Outcome::Allow,
            reason: "ok".into(), trace_id: "trace-1".into(),
            signature: "ms003".into(),
        }
    }

    fn ok_snap() -> StateSnapshot {
        StateSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T03:00:00Z".into(),
            active_profile: Profile::Careful,
            active_network_profile: NetworkProfile::PackageRegistries,
            actor_registry: ok_registry(),
            active_capability_word_hex: "0xff00ff00ff00ff00".into(),
            last_policy_decision: Some(ok_policy()),
            recent_spans: vec![ok_span()],
            envelope_signature: "ms003-envelope".into(),
        }
    }

    #[test]
    fn ok_snapshot_validates() {
        ok_snap().validate().unwrap();
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = ok_snap();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), SnapshotError::SchemaMismatch { .. }));
    }

    #[test]
    fn missing_captured_at_rejected() {
        let mut s = ok_snap();
        s.captured_at = String::new();
        assert!(matches!(s.validate().unwrap_err(), SnapshotError::CapturedAtMissing));
    }

    #[test]
    fn missing_envelope_signature_rejected() {
        let mut s = ok_snap();
        s.envelope_signature = String::new();
        assert!(matches!(s.validate().unwrap_err(), SnapshotError::EnvelopeUnsigned));
    }

    #[test]
    fn invalid_capability_word_rejected() {
        let mut s = ok_snap();
        s.active_capability_word_hex = "not-hex".into();
        assert!(matches!(s.validate().unwrap_err(), SnapshotError::CapabilityWordInvalid(_)));
    }

    #[test]
    fn bad_embedded_actor_registry_caught() {
        let mut s = ok_snap();
        s.actor_registry.signature = String::new();
        assert!(matches!(s.validate().unwrap_err(), SnapshotError::ActorRegistryInvalid(_)));
    }

    #[test]
    fn bad_embedded_span_caught() {
        let mut s = ok_snap();
        s.recent_spans[0].trace_id = String::new();
        assert!(matches!(s.validate().unwrap_err(), SnapshotError::SpansInvalid(_)));
    }

    #[test]
    fn bad_embedded_policy_decision_caught() {
        let mut s = ok_snap();
        if let Some(p) = s.last_policy_decision.as_mut() {
            p.subject = String::new();
        }
        assert!(matches!(s.validate().unwrap_err(), SnapshotError::PolicyDecisionInvalid(_)));
    }

    #[test]
    fn no_policy_decision_still_validates() {
        let mut s = ok_snap();
        s.last_policy_decision = None;
        s.validate().unwrap();
    }

    #[test]
    fn canonical_path_const() {
        assert_eq!(StateSnapshot::canonical_path(), "/var/lib/selfdef/state-snapshot.json");
        assert_eq!(SNAPSHOT_PATH, "/var/lib/selfdef/state-snapshot.json");
    }

    #[test]
    fn snapshot_serde_roundtrip() {
        let s = ok_snap();
        let j = serde_json::to_string(&s).unwrap();
        let back: StateSnapshot = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
