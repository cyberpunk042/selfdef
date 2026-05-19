//! `selfdef-event-emitter` — composite that wires one decision into 4 surfaces.
//!
//! For every L4+ action decided by the daemon, this crate emits a coordinated
//! tuple of (PolicyDecision, TraceSpan, AuditRecord, DispatchPlan) so that the
//! 4 downstream surfaces (M049 trace, MS016 audit log, MS027 observability,
//! MS033 policy bus) stay perfectly aligned.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_audit_log_writer::AuditRecord;
use selfdef_policy_bus::{plan as bus_plan, DispatchPlan};
use selfdef_policy_decision::{PolicyDecision, Outcome};
use selfdef_trace_span::TraceSpan;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One coordinated emission record — the 4-tuple every L4+ action produces.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EmissionBundle {
    /// Wire schema version.
    pub schema_version: String,
    /// MS033 10-field policy decision.
    pub decision: PolicyDecision,
    /// M049 13-field trace span.
    pub span: TraceSpan,
    /// MS016 atomic audit record.
    pub audit: AuditRecord,
    /// MS033 dispatch plan (which subsystems fan out).
    pub plan: DispatchPlan,
}

/// Errors.
#[derive(Debug, Error)]
pub enum EmitterError {
    /// Decision invalid.
    #[error("policy decision invalid: {0}")]
    DecisionInvalid(String),
    /// Span invalid.
    #[error("trace span invalid: {0}")]
    SpanInvalid(String),
    /// Audit record invalid.
    #[error("audit record invalid: {0}")]
    AuditInvalid(String),
    /// Bus dispatch plan failed.
    #[error("bus dispatch failed: {0}")]
    BusFailed(String),
    /// Cross-component trace_id mismatch.
    #[error("trace_id mismatch: decision={decision} span={span} audit={audit}")]
    TraceIdMismatch {
        /// Decision's trace_id.
        decision: String,
        /// Span's trace_id.
        span: String,
        /// Audit's trace_id.
        audit: String,
    },
}

/// Build a coordinated 4-tuple emission bundle from the 3 inputs + dispatch plan.
/// Cross-validates that all three carry the same trace_id.
pub fn emit(
    decision: PolicyDecision,
    span: TraceSpan,
    audit: AuditRecord,
) -> Result<EmissionBundle, EmitterError> {
    // Validate each sub-component
    decision.validate().map_err(|e| EmitterError::DecisionInvalid(e.to_string()))?;
    selfdef_trace_span::validate(&span).map_err(|e| EmitterError::SpanInvalid(e.to_string()))?;
    audit.validate().map_err(|e| EmitterError::AuditInvalid(e.to_string()))?;

    // Cross-validate trace_id consistency
    if decision.trace_id != span.trace_id || span.trace_id != audit.trace_id {
        return Err(EmitterError::TraceIdMismatch {
            decision: decision.trace_id.clone(),
            span: span.trace_id.clone(),
            audit: audit.trace_id.clone(),
        });
    }

    // Build dispatch plan
    let plan = bus_plan(&decision).map_err(|e| EmitterError::BusFailed(e.to_string()))?;

    Ok(EmissionBundle {
        schema_version: SCHEMA_VERSION.into(),
        decision,
        span,
        audit,
        plan,
    })
}

impl EmissionBundle {
    /// Whether the decision allowed the action to proceed.
    pub fn proceeds(&self) -> bool {
        self.decision.outcome == Outcome::Allow
    }

    /// Number of subsystems the bundle will fan out to.
    pub fn fanout(&self) -> usize {
        self.plan.subsystems.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_policy_decision::{ContextSensitivity, RiskClass, SideEffectClass, UserApprovalState};
    use selfdef_trace_span::{HardwareTarget, PolicyResult};

    fn ok_decision(trace: &str) -> PolicyDecision {
        PolicyDecision {
            schema_version: "1.0.0".into(),
            subject: "op".into(),
            action: "fs.write".into(),
            resource: "/workspace/x".into(),
            intent: "ship".into(),
            profile: "careful".into(),
            risk: RiskClass::Low,
            model_provider: "local:rocm-3090".into(),
            context_sensitivity: ContextSensitivity::Internal,
            side_effect_class: SideEffectClass::FsWrite,
            user_approval: UserApprovalState::NotRequired,
            outcome: Outcome::Allow,
            reason: "ok".into(),
            trace_id: trace.into(),
            signature: "ms003".into(),
        }
    }

    fn ok_span(trace: &str) -> TraceSpan {
        TraceSpan {
            schema_version: "1.0.0".into(),
            trace_id: trace.into(),
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

    fn ok_audit(trace: &str) -> AuditRecord {
        AuditRecord {
            schema_version: "1.0.0".into(),
            at: "2026-05-19T03:00:00Z".into(),
            trace_id: trace.into(),
            actor: "operator-fp".into(),
            kind: "policy-decision".into(),
            summary: "fs.write allowed".into(),
            prev_chain_hash: "0x00".into(),
            chain_hash: "0xaa".into(),
        }
    }

    #[test]
    fn ok_bundle_emits_with_matching_trace_ids() {
        let b = emit(ok_decision("trace-001"), ok_span("trace-001"), ok_audit("trace-001")).unwrap();
        assert!(b.proceeds());
        assert!(b.fanout() >= 4); // baselines always fire
    }

    #[test]
    fn mismatched_trace_ids_caught() {
        let err = emit(ok_decision("a"), ok_span("b"), ok_audit("c")).unwrap_err();
        match err {
            EmitterError::TraceIdMismatch { decision, span, audit } => {
                assert_eq!(decision, "a");
                assert_eq!(span, "b");
                assert_eq!(audit, "c");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn invalid_decision_caught() {
        let mut bad = ok_decision("trace-1");
        bad.subject = String::new();
        assert!(matches!(
            emit(bad, ok_span("trace-1"), ok_audit("trace-1")).unwrap_err(),
            EmitterError::DecisionInvalid(_)
        ));
    }

    #[test]
    fn invalid_span_caught() {
        let mut bad = ok_span("trace-1");
        bad.profile = String::new();
        assert!(matches!(
            emit(ok_decision("trace-1"), bad, ok_audit("trace-1")).unwrap_err(),
            EmitterError::SpanInvalid(_)
        ));
    }

    #[test]
    fn invalid_audit_caught() {
        let mut bad = ok_audit("trace-1");
        bad.kind = String::new();
        assert!(matches!(
            emit(ok_decision("trace-1"), ok_span("trace-1"), bad).unwrap_err(),
            EmitterError::AuditInvalid(_)
        ));
    }

    #[test]
    fn deny_bundle_fans_to_more_subsystems() {
        let mut d = ok_decision("trace-1");
        d.outcome = Outcome::Deny;
        let b = emit(d, ok_span("trace-1"), ok_audit("trace-1")).unwrap();
        assert!(!b.proceeds());
        // Deny adds NotifyChain → fanout >= 5
        assert!(b.fanout() >= 5);
    }

    #[test]
    fn ask_bundle_fans_to_operator_queue() {
        let mut d = ok_decision("trace-1");
        d.outcome = Outcome::Ask;
        let mut s = ok_span("trace-1");
        s.policy_result = PolicyResult::Ask;
        let b = emit(d, s, ok_audit("trace-1")).unwrap();
        // Ask adds NotifyChain + OperatorQueue → fanout >= 6
        assert!(b.fanout() >= 6);
    }

    #[test]
    fn bundle_serde_roundtrip() {
        let b = emit(ok_decision("trace-1"), ok_span("trace-1"), ok_audit("trace-1")).unwrap();
        let j = serde_json::to_string(&b).unwrap();
        let back: EmissionBundle = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
