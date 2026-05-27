//! `selfdef-policy-bus` — MS033 dispatch fabric for PolicyDecision routing.
//!
//! Per MS033 + E0332 + F03899-F03902:
//! - MS027 observability EMITS the trace event objects (F03899)
//! - MS025 detect-host event-bus TRANSPORTS the trace events (F03901)
//! - MS003 correlator + store + responder PROCESSES the trace events (F03902)
//!
//! This crate is the in-process dispatch fabric that takes a typed
//! PolicyDecision and routes it to the right downstream subsystem.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_policy_decision::{Outcome, PolicyDecision, RiskClass, SideEffectClass};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Downstream subsystems per F03899-F03902.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BusSubsystem {
    /// MS027 observability — emit OCSF event.
    Observability,
    /// MS025 detect-host event-bus — transport the trace.
    EventBus,
    /// MS003 correlator+store+responder — process the event.
    Correlator,
    /// MS016 atomic ZFS audit log — append the durable record.
    AuditLog,
    /// Notify chain (MS004 12-channel adapters) — operator alert.
    NotifyChain,
    /// D-06 pending-approvals queue.
    OperatorQueue,
}

/// Dispatch plan — which subsystems the policy decision fans out to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DispatchPlan {
    /// Schema version.
    pub schema_version: String,
    /// Subsystems to dispatch to (ordered).
    pub subsystems: Vec<BusSubsystem>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BusError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Decision invalid per its own validate().
    #[error("policy decision invalid: {0}")]
    InvalidDecision(String),
}

/// Compute the dispatch plan for a policy decision.
pub fn plan(decision: &PolicyDecision) -> Result<DispatchPlan, BusError> {
    decision
        .validate()
        .map_err(|e| BusError::InvalidDecision(e.to_string()))?;

    // Every decision fans out to Observability + EventBus + Correlator + AuditLog.
    let mut subsystems = vec![
        BusSubsystem::Observability,
        BusSubsystem::EventBus,
        BusSubsystem::Correlator,
        BusSubsystem::AuditLog,
    ];

    // Notify chain fires on Deny + Ask + Sandbox (not Allow).
    if decision.outcome != Outcome::Allow {
        subsystems.push(BusSubsystem::NotifyChain);
    }

    // OperatorQueue fires on Ask outcome OR Critical risk OR Persistent side-effect.
    if decision.outcome == Outcome::Ask
        || decision.risk == RiskClass::Critical
        || decision.side_effect_class == SideEffectClass::Persistent
    {
        subsystems.push(BusSubsystem::OperatorQueue);
    }

    Ok(DispatchPlan {
        schema_version: SCHEMA_VERSION.into(),
        subsystems,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_policy_decision::{ContextSensitivity, UserApprovalState};

    fn ok_decision() -> PolicyDecision {
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
            trace_id: "trace-1".into(),
            signature: "ms003".into(),
        }
    }

    #[test]
    fn allow_low_risk_fans_to_4_baselines() {
        let p = plan(&ok_decision()).unwrap();
        assert_eq!(p.subsystems.len(), 4);
        assert!(p.subsystems.contains(&BusSubsystem::Observability));
        assert!(p.subsystems.contains(&BusSubsystem::EventBus));
        assert!(p.subsystems.contains(&BusSubsystem::Correlator));
        assert!(p.subsystems.contains(&BusSubsystem::AuditLog));
        assert!(!p.subsystems.contains(&BusSubsystem::NotifyChain));
        assert!(!p.subsystems.contains(&BusSubsystem::OperatorQueue));
    }

    #[test]
    fn deny_adds_notify_chain() {
        let mut d = ok_decision();
        d.outcome = Outcome::Deny;
        let p = plan(&d).unwrap();
        assert!(p.subsystems.contains(&BusSubsystem::NotifyChain));
        assert!(!p.subsystems.contains(&BusSubsystem::OperatorQueue));
    }

    #[test]
    fn ask_adds_both_notify_and_operator_queue() {
        let mut d = ok_decision();
        d.outcome = Outcome::Ask;
        let p = plan(&d).unwrap();
        assert!(p.subsystems.contains(&BusSubsystem::NotifyChain));
        assert!(p.subsystems.contains(&BusSubsystem::OperatorQueue));
    }

    #[test]
    fn sandbox_adds_notify_only() {
        let mut d = ok_decision();
        d.outcome = Outcome::Sandbox;
        let p = plan(&d).unwrap();
        assert!(p.subsystems.contains(&BusSubsystem::NotifyChain));
        assert!(!p.subsystems.contains(&BusSubsystem::OperatorQueue));
    }

    #[test]
    fn critical_risk_adds_operator_queue_even_on_allow() {
        let mut d = ok_decision();
        d.risk = RiskClass::Critical;
        d.user_approval = UserApprovalState::Approved; // satisfy PolicyDecision validate()
        let p = plan(&d).unwrap();
        assert!(p.subsystems.contains(&BusSubsystem::OperatorQueue));
    }

    #[test]
    fn persistent_side_effect_adds_operator_queue() {
        let mut d = ok_decision();
        d.side_effect_class = SideEffectClass::Persistent;
        d.user_approval = UserApprovalState::Approved; // satisfy PolicyDecision validate()
        let p = plan(&d).unwrap();
        assert!(p.subsystems.contains(&BusSubsystem::OperatorQueue));
    }

    #[test]
    fn invalid_decision_rejected() {
        let mut d = ok_decision();
        d.subject = String::new();
        assert!(matches!(
            plan(&d).unwrap_err(),
            BusError::InvalidDecision(_)
        ));
    }

    #[test]
    fn six_subsystems_enumerated() {
        // Sanity check the enum.
        let all = [
            BusSubsystem::Observability,
            BusSubsystem::EventBus,
            BusSubsystem::Correlator,
            BusSubsystem::AuditLog,
            BusSubsystem::NotifyChain,
            BusSubsystem::OperatorQueue,
        ];
        assert_eq!(all.len(), 6);
    }

    #[test]
    fn bus_subsystem_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&BusSubsystem::EventBus).unwrap(),
            "\"event-bus\""
        );
        assert_eq!(
            serde_json::to_string(&BusSubsystem::NotifyChain).unwrap(),
            "\"notify-chain\""
        );
        assert_eq!(
            serde_json::to_string(&BusSubsystem::OperatorQueue).unwrap(),
            "\"operator-queue\""
        );
        assert_eq!(
            serde_json::to_string(&BusSubsystem::AuditLog).unwrap(),
            "\"audit-log\""
        );
    }

    #[test]
    fn plan_serde_roundtrip() {
        let p = plan(&ok_decision()).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: DispatchPlan = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
