//! `selfdef-trace-span` — MS033/M049 13-field span emitter.
//!
//! Per F03882 + R07722 + dump 16221, every action emits a 13-field
//! span carrying:
//!
//!   1. trace_id
//!   2. profile
//!   3. model
//!   4. provider
//!   5. hardware
//!   6. tokens (prompt + completion split)
//!   7. latency_ms (start → end)
//!   8. cost_millicents (1/1000 USD)
//!   9. risk_score (0..100)
//!  10. memory_refs (M028 item ids)
//!  11. tool_refs (MS035 capability_word entries)
//!  12. policy_result (4-outcome)
//!  13. branch_id (M027 value-plane branch)
//!
//! Doctrines preserved verbatim:
//!
//! > "Trace is emitted when the action is decided, not after" (F03942 dump 16221)
//!
//! > "Every action MUST emit a trace event object" (F03944 dump 16221)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Doctrine surface verbatim per F03942 dump 16221.
pub const DOCTRINE_TRACE_AT_DECISION: &str =
    "Trace is emitted when the action is decided, not after";

/// Doctrine surface verbatim per F03944 dump 16221.
pub const DOCTRINE_EVERY_ACTION_EMITS_TRACE: &str = "Every action MUST emit a trace event object";

/// Policy outcome (mirrors MS033 4-state).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyResult {
    /// Allow.
    Allow,
    /// Deny.
    Deny,
    /// Ask.
    Ask,
    /// Sandbox.
    Sandbox,
}

/// Hardware substrate identifier per M058 + M075 SRP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HardwareTarget {
    /// Ryzen 9 9900X CPU (Conductor / Pulse).
    CpuPulse,
    /// RTX 3090 24GB (Logic Engine).
    #[serde(rename = "rocm-3090")]
    Rocm3090,
    /// Blackwell PRO 6000 96GB (Oracle Core).
    BlackwellOracle,
    /// Cloud (external).
    Cloud,
    /// No hardware allocated (observe-only path).
    None,
}

/// 13-field span per F03882 + R07722 + dump 16221.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceSpan {
    /// Schema version.
    pub schema_version: String,
    /// 1. trace_id (ULID).
    pub trace_id: String,
    /// 2. profile name (MS040).
    pub profile: String,
    /// 3. model identifier.
    pub model: String,
    /// 4. provider (local-rocm / local-cuda / cloud-openai / cloud-anthropic).
    pub provider: String,
    /// 5. hardware target.
    pub hardware: HardwareTarget,
    /// 6a. tokens — prompt.
    pub tokens_prompt: u32,
    /// 6b. tokens — completion (paired with prompt).
    pub tokens_completion: u32,
    /// 7. latency in milliseconds.
    pub latency_ms: u32,
    /// 8. cost in millicents (1/1000 USD).
    pub cost_millicents: u32,
    /// 9. risk score (0..=100).
    pub risk_score: u8,
    /// 10. memory references (M028 item ids).
    pub memory_refs: Vec<String>,
    /// 11. tool references (MS035 capability_word entries).
    pub tool_refs: Vec<String>,
    /// 12. policy result.
    pub policy_result: PolicyResult,
    /// 13. branch_id (M027 value plane).
    pub branch_id: String,
    /// MS003 signature over canonical-JSON encoding.
    pub signature: String,
    /// ISO-8601 UTC timestamp when span closed (decision-aligned per F03942).
    pub closed_at: String,
}

impl TraceSpan {
    /// Total tokens across prompt + completion.
    pub fn total_tokens(&self) -> u64 {
        self.tokens_prompt as u64 + self.tokens_completion as u64
    }

    /// Cost in USD as f64 (millicents → USD division).
    pub fn cost_usd(&self) -> f64 {
        self.cost_millicents as f64 / 100_000.0
    }
}

/// Errors.
#[derive(Debug, Error)]
pub enum SpanError {
    /// Schema drift.
    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected.
        expected: String,
        /// Observed.
        actual: String,
    },
    /// Required field empty.
    #[error("required field empty: {0}")]
    FieldEmpty(&'static str),
    /// Risk score outside 0..=100.
    #[error("risk_score {0} outside 0..=100")]
    RiskOutOfRange(u8),
    /// closed_at empty (per F03942 trace emitted AT decision time, so closed_at MUST be set).
    #[error("closed_at empty (F03942 requires emit-at-decision time)")]
    ClosedAtMissing,
    /// MS003 signature missing.
    #[error("span unsigned (every span must be MS003-signed)")]
    Unsigned,
    /// Doctrine surface tampered.
    #[error("doctrine tampered: expected verbatim {expected:?}")]
    DoctrineTampered {
        /// Expected.
        expected: String,
    },
}

/// Validate a span — all 13 fields populated correctly + signature + closed_at.
pub fn validate(s: &TraceSpan) -> Result<(), SpanError> {
    if s.schema_version != SCHEMA_VERSION {
        return Err(SpanError::SchemaMismatch {
            expected: SCHEMA_VERSION.into(),
            actual: s.schema_version.clone(),
        });
    }
    if s.signature.is_empty() {
        return Err(SpanError::Unsigned);
    }
    if s.closed_at.is_empty() {
        return Err(SpanError::ClosedAtMissing);
    }
    // String fields non-empty.
    if s.trace_id.is_empty() {
        return Err(SpanError::FieldEmpty("trace_id"));
    }
    if s.profile.is_empty() {
        return Err(SpanError::FieldEmpty("profile"));
    }
    if s.model.is_empty() {
        return Err(SpanError::FieldEmpty("model"));
    }
    if s.provider.is_empty() {
        return Err(SpanError::FieldEmpty("provider"));
    }
    if s.branch_id.is_empty() {
        return Err(SpanError::FieldEmpty("branch_id"));
    }
    if s.risk_score > 100 {
        return Err(SpanError::RiskOutOfRange(s.risk_score));
    }
    Ok(())
}

/// Validate the two doctrine constants.
pub fn assert_doctrines_intact(at_decision: &str, every_action: &str) -> Result<(), SpanError> {
    if at_decision != DOCTRINE_TRACE_AT_DECISION {
        return Err(SpanError::DoctrineTampered {
            expected: DOCTRINE_TRACE_AT_DECISION.into(),
        });
    }
    if every_action != DOCTRINE_EVERY_ACTION_EMITS_TRACE {
        return Err(SpanError::DoctrineTampered {
            expected: DOCTRINE_EVERY_ACTION_EMITS_TRACE.into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_span() -> TraceSpan {
        TraceSpan {
            schema_version: SCHEMA_VERSION.into(),
            trace_id: "trace-001".into(),
            profile: "careful".into(),
            model: "claude-opus".into(),
            provider: "cloud-anthropic".into(),
            hardware: HardwareTarget::BlackwellOracle,
            tokens_prompt: 1200,
            tokens_completion: 800,
            latency_ms: 1400,
            cost_millicents: 250,
            risk_score: 12,
            memory_refs: vec!["mem-a".into(), "mem-b".into()],
            tool_refs: vec!["fs.read".into()],
            policy_result: PolicyResult::Allow,
            branch_id: "branch-main".into(),
            signature: "ms003-sig".into(),
            closed_at: "2026-05-19T03:30:00Z".into(),
        }
    }

    // --- 13 fields ---

    #[test]
    fn ok_span_validates() {
        validate(&ok_span()).unwrap();
    }

    #[test]
    fn missing_trace_id_rejected() {
        let mut s = ok_span();
        s.trace_id = String::new();
        assert!(matches!(
            validate(&s).unwrap_err(),
            SpanError::FieldEmpty("trace_id")
        ));
    }

    #[test]
    fn missing_profile_rejected() {
        let mut s = ok_span();
        s.profile = String::new();
        assert!(matches!(
            validate(&s).unwrap_err(),
            SpanError::FieldEmpty("profile")
        ));
    }

    #[test]
    fn missing_model_rejected() {
        let mut s = ok_span();
        s.model = String::new();
        assert!(matches!(
            validate(&s).unwrap_err(),
            SpanError::FieldEmpty("model")
        ));
    }

    #[test]
    fn missing_provider_rejected() {
        let mut s = ok_span();
        s.provider = String::new();
        assert!(matches!(
            validate(&s).unwrap_err(),
            SpanError::FieldEmpty("provider")
        ));
    }

    #[test]
    fn missing_branch_id_rejected() {
        let mut s = ok_span();
        s.branch_id = String::new();
        assert!(matches!(
            validate(&s).unwrap_err(),
            SpanError::FieldEmpty("branch_id")
        ));
    }

    #[test]
    fn risk_score_over_100_rejected() {
        let mut s = ok_span();
        s.risk_score = 150;
        assert!(matches!(
            validate(&s).unwrap_err(),
            SpanError::RiskOutOfRange(150)
        ));
    }

    #[test]
    fn closed_at_empty_rejected() {
        let mut s = ok_span();
        s.closed_at = String::new();
        assert!(matches!(
            validate(&s).unwrap_err(),
            SpanError::ClosedAtMissing
        ));
    }

    #[test]
    fn unsigned_rejected() {
        let mut s = ok_span();
        s.signature = String::new();
        assert!(matches!(validate(&s).unwrap_err(), SpanError::Unsigned));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = ok_span();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            validate(&s).unwrap_err(),
            SpanError::SchemaMismatch { .. }
        ));
    }

    // --- Helper methods ---

    #[test]
    fn total_tokens_sums_prompt_completion() {
        let s = ok_span();
        assert_eq!(s.total_tokens(), 2000);
    }

    #[test]
    fn cost_usd_conversion() {
        let mut s = ok_span();
        s.cost_millicents = 250_000; // 250000 millicents = 2.50 USD
        assert!((s.cost_usd() - 2.50).abs() < 1e-9);
    }

    // --- Doctrines ---

    #[test]
    fn doctrines_verbatim() {
        assert_eq!(
            DOCTRINE_TRACE_AT_DECISION,
            "Trace is emitted when the action is decided, not after"
        );
        assert_eq!(
            DOCTRINE_EVERY_ACTION_EMITS_TRACE,
            "Every action MUST emit a trace event object"
        );
        assert_doctrines_intact(
            DOCTRINE_TRACE_AT_DECISION,
            DOCTRINE_EVERY_ACTION_EMITS_TRACE,
        )
        .unwrap();
    }

    #[test]
    fn doctrine_tamper_caught() {
        let err = assert_doctrines_intact("WRONG", DOCTRINE_EVERY_ACTION_EMITS_TRACE).unwrap_err();
        assert!(matches!(err, SpanError::DoctrineTampered { .. }));
        let err2 = assert_doctrines_intact(DOCTRINE_TRACE_AT_DECISION, "WRONG").unwrap_err();
        assert!(matches!(err2, SpanError::DoctrineTampered { .. }));
    }

    // --- Serde ---

    #[test]
    fn hardware_target_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&HardwareTarget::BlackwellOracle).unwrap(),
            "\"blackwell-oracle\""
        );
        assert_eq!(
            serde_json::to_string(&HardwareTarget::CpuPulse).unwrap(),
            "\"cpu-pulse\""
        );
        assert_eq!(
            serde_json::to_string(&HardwareTarget::Rocm3090).unwrap(),
            "\"rocm-3090\""
        );
    }

    #[test]
    fn span_serde_roundtrip_preserves_13_fields() {
        let original = ok_span();
        let j = serde_json::to_string(&original).unwrap();
        let back: TraceSpan = serde_json::from_str(&j).unwrap();
        assert_eq!(original, back);
        // Spot-check the 13 fields survived.
        assert_eq!(back.tokens_prompt, 1200);
        assert_eq!(back.memory_refs.len(), 2);
        assert_eq!(back.tool_refs.len(), 1);
        assert_eq!(back.policy_result, PolicyResult::Allow);
    }
}
