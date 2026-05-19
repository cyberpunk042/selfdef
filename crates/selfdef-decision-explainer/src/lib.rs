//! `selfdef-decision-explainer` — operator-readable rationale chain.
//!
//! Given a `PolicyDecision`, returns an `Explanation` with:
//! - `headline`     — one-sentence summary
//! - `factors`      — ordered list of evidence strings the daemon
//!                    considered
//! - `outcome_class`— derived signal: `:routine`, `:elevated`,
//!                    `:operator-attention`, `:blocked`
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_policy_decision::{
    Outcome, PolicyDecision, RiskClass, SideEffectClass, UserApprovalState,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Outcome class for visual styling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutcomeClass {
    /// Routine Allow with no special factors.
    Routine,
    /// Allow but with elevated risk or side-effect.
    Elevated,
    /// Outcome was Ask — operator must decide.
    OperatorAttention,
    /// Outcome was Deny or Sandbox.
    Blocked,
}

/// Explanation envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Explanation {
    /// Schema version.
    pub schema_version: String,
    /// Trace_id of the decision.
    pub trace_id: String,
    /// One-line headline (≤120 chars).
    pub headline: String,
    /// Ordered factor strings.
    pub factors: Vec<String>,
    /// Outcome class.
    pub outcome_class: OutcomeClass,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ExplainError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Headline > 120 chars.
    #[error("headline length {0} > 120")]
    HeadlineTooLong(usize),
    /// Empty factor.
    #[error("factor at index {0} empty")]
    EmptyFactor(usize),
}

/// Build the explanation from a decision.
pub fn explain(decision: &PolicyDecision) -> Explanation {
    let mut factors = Vec::new();
    factors.push(format!("subject={}", decision.subject));
    factors.push(format!("action={}", decision.action));
    factors.push(format!("resource={}", decision.resource));
    factors.push(format!("profile={}", decision.profile));
    factors.push(format!("risk={:?}", decision.risk));
    factors.push(format!("side_effect={:?}", decision.side_effect_class));
    factors.push(format!("model_provider={}", decision.model_provider));
    factors.push(format!("user_approval={:?}", decision.user_approval));
    if !decision.reason.is_empty() {
        factors.push(format!("reason={}", decision.reason));
    }

    let outcome_class = classify(decision);
    let headline = headline_for(decision, outcome_class);

    Explanation {
        schema_version: SCHEMA_VERSION.into(),
        trace_id: decision.trace_id.clone(),
        headline,
        factors,
        outcome_class,
    }
}

fn classify(decision: &PolicyDecision) -> OutcomeClass {
    match decision.outcome {
        Outcome::Deny | Outcome::Sandbox => OutcomeClass::Blocked,
        Outcome::Ask => OutcomeClass::OperatorAttention,
        Outcome::Allow => {
            if decision.risk >= RiskClass::High
                || matches!(
                    decision.side_effect_class,
                    SideEffectClass::Persistent | SideEffectClass::NetworkEgress | SideEffectClass::Process
                )
                || decision.user_approval == UserApprovalState::Approved
            {
                OutcomeClass::Elevated
            } else {
                OutcomeClass::Routine
            }
        }
    }
}

fn headline_for(decision: &PolicyDecision, class: OutcomeClass) -> String {
    let outcome = match decision.outcome {
        Outcome::Allow => "ALLOW",
        Outcome::Deny => "DENY",
        Outcome::Ask => "ASK",
        Outcome::Sandbox => "SANDBOX",
    };
    let mut h = format!(
        "{outcome}: {} {} on {} (risk {:?}, side-effect {:?}) [{class:?}]",
        decision.subject, decision.action, decision.resource, decision.risk, decision.side_effect_class,
    );
    if h.chars().count() > 120 {
        // Truncate to 120 chars (boundary-safe).
        let mut s = String::new();
        for c in h.chars().take(120) { s.push(c); }
        h = s;
    }
    h
}

impl Explanation {
    /// Validate.
    pub fn validate(&self) -> Result<(), ExplainError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ExplainError::SchemaMismatch);
        }
        let n = self.headline.chars().count();
        if n > 120 { return Err(ExplainError::HeadlineTooLong(n)); }
        for (i, f) in self.factors.iter().enumerate() {
            if f.is_empty() { return Err(ExplainError::EmptyFactor(i)); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_policy_decision::{ContextSensitivity, UserApprovalState};

    fn d(outcome: Outcome, sec: SideEffectClass, risk: RiskClass) -> PolicyDecision {
        let approval = if outcome == Outcome::Allow
            && (sec == SideEffectClass::Persistent || risk == RiskClass::Critical)
        {
            UserApprovalState::Approved
        } else {
            UserApprovalState::NotRequired
        };
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
            side_effect_class: sec,
            user_approval: approval,
            outcome,
            reason: "ok".into(),
            trace_id: "tr-1".into(),
            signature: "sig".into(),
        }
    }

    #[test]
    fn allow_low_routine() {
        let e = explain(&d(Outcome::Allow, SideEffectClass::ReadOnly, RiskClass::Low));
        assert_eq!(e.outcome_class, OutcomeClass::Routine);
        e.validate().unwrap();
    }

    #[test]
    fn allow_high_risk_elevated() {
        let e = explain(&d(Outcome::Allow, SideEffectClass::ReadOnly, RiskClass::High));
        assert_eq!(e.outcome_class, OutcomeClass::Elevated);
    }

    #[test]
    fn allow_persistent_elevated() {
        let e = explain(&d(Outcome::Allow, SideEffectClass::Persistent, RiskClass::Low));
        assert_eq!(e.outcome_class, OutcomeClass::Elevated);
    }

    #[test]
    fn allow_network_egress_elevated() {
        let e = explain(&d(Outcome::Allow, SideEffectClass::NetworkEgress, RiskClass::Low));
        assert_eq!(e.outcome_class, OutcomeClass::Elevated);
    }

    #[test]
    fn allow_process_elevated() {
        let e = explain(&d(Outcome::Allow, SideEffectClass::Process, RiskClass::Low));
        assert_eq!(e.outcome_class, OutcomeClass::Elevated);
    }

    #[test]
    fn ask_attention() {
        let e = explain(&d(Outcome::Ask, SideEffectClass::ReadOnly, RiskClass::Low));
        assert_eq!(e.outcome_class, OutcomeClass::OperatorAttention);
    }

    #[test]
    fn deny_blocked() {
        let e = explain(&d(Outcome::Deny, SideEffectClass::ReadOnly, RiskClass::Low));
        assert_eq!(e.outcome_class, OutcomeClass::Blocked);
    }

    #[test]
    fn sandbox_blocked() {
        let e = explain(&d(Outcome::Sandbox, SideEffectClass::FsWrite, RiskClass::Medium));
        assert_eq!(e.outcome_class, OutcomeClass::Blocked);
    }

    #[test]
    fn factors_include_essential_fields() {
        let e = explain(&d(Outcome::Allow, SideEffectClass::ReadOnly, RiskClass::Low));
        assert!(e.factors.iter().any(|f| f.starts_with("subject=alice")));
        assert!(e.factors.iter().any(|f| f.starts_with("action=fs.write")));
        assert!(e.factors.iter().any(|f| f.starts_with("risk=Low")));
    }

    #[test]
    fn headline_under_120_chars() {
        let e = explain(&d(Outcome::Allow, SideEffectClass::ReadOnly, RiskClass::Low));
        assert!(e.headline.chars().count() <= 120);
    }

    #[test]
    fn outcome_class_serde_kebab() {
        assert_eq!(serde_json::to_string(&OutcomeClass::Routine).unwrap(), "\"routine\"");
        assert_eq!(serde_json::to_string(&OutcomeClass::OperatorAttention).unwrap(), "\"operator-attention\"");
    }

    #[test]
    fn explanation_serde_roundtrip() {
        let e = explain(&d(Outcome::Ask, SideEffectClass::FsWrite, RiskClass::Medium));
        let j = serde_json::to_string(&e).unwrap();
        let back: Explanation = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }
}
