//! `selfdef-high-risk-triple-gate` — MS041 commit-authority triple gate.
//!
//! For actions classed as `Persistent` (durable change) or carrying
//! `Risk::Critical`, the IPS demands three independent approvals before
//! Allow is admissible:
//!
//! 1. **Snapshot** — ZFS snapshot taken before the action.
//! 2. **Eval** — eval gate of the kind required by the SideEffectClass
//!    (per `selfdef-eval-gate-policy`) passed within staleness window.
//! 3. **Oracle-or-human** — either an Oracle (LLM-as-judge) approved
//!    OR an operator human-acknowledged the action.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_eval_gate_policy::{EvalGateError, EvalGatePolicy};
use selfdef_policy_decision::{RiskClass, SideEffectClass};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Inputs to the triple gate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TripleGateInput {
    /// Side-effect class.
    pub side_effect: SideEffectClass,
    /// Risk class.
    pub risk: RiskClass,
    /// Has a fresh ZFS snapshot been taken?
    pub snapshot_taken: bool,
    /// Last successful eval pass (seconds ago); `None` = never.
    pub eval_last_pass_seconds_ago: Option<u32>,
    /// Did an Oracle (LLM-judge) approve this action?
    pub oracle_approved: bool,
    /// Did a human operator approve this action?
    pub human_approved: bool,
}

/// Errors.
#[derive(Debug, Error)]
pub enum TripleGateError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Snapshot missing.
    #[error("snapshot required")]
    SnapshotMissing,
    /// Eval gate failed.
    #[error("eval gate failed: {0}")]
    EvalFailed(String),
    /// Neither oracle nor human approved.
    #[error("oracle-or-human approval required")]
    OracleOrHumanRequired,
}

/// True if the action needs the triple gate.
pub fn requires_triple_gate(side_effect: SideEffectClass, risk: RiskClass) -> bool {
    side_effect == SideEffectClass::Persistent || risk == RiskClass::Critical
}

/// Run the triple gate. Returns `Ok(())` if all sub-gates clear.
pub fn run_triple_gate(
    input: &TripleGateInput,
    eval_policy: &EvalGatePolicy,
) -> Result<(), TripleGateError> {
    if !requires_triple_gate(input.side_effect, input.risk) {
        return Ok(());
    }
    // 1. Snapshot
    if !input.snapshot_taken {
        return Err(TripleGateError::SnapshotMissing);
    }
    // 2. Eval gate
    if let Err(e) = eval_policy.admit(input.side_effect, input.eval_last_pass_seconds_ago) {
        let msg = match e {
            EvalGateError::Stale {
                gate, age, limit, ..
            } => {
                format!("{gate:?} stale: {age}s > {limit}s")
            }
            EvalGateError::NeverPassed { gate, .. } => format!("{gate:?} never passed"),
            other => other.to_string(),
        };
        return Err(TripleGateError::EvalFailed(msg));
    }
    // 3. Oracle-or-human
    if !(input.oracle_approved || input.human_approved) {
        return Err(TripleGateError::OracleOrHumanRequired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(sec: SideEffectClass, risk: RiskClass) -> TripleGateInput {
        TripleGateInput {
            side_effect: sec,
            risk,
            snapshot_taken: false,
            eval_last_pass_seconds_ago: None,
            oracle_approved: false,
            human_approved: false,
        }
    }

    #[test]
    fn no_gate_needed_for_low_risk_read_only() {
        let i = input(SideEffectClass::ReadOnly, RiskClass::Low);
        run_triple_gate(&i, &EvalGatePolicy::canonical()).unwrap();
    }

    #[test]
    fn persistent_requires_triple_gate() {
        let mut i = input(SideEffectClass::Persistent, RiskClass::Low);
        // No snapshot → fail
        assert!(matches!(
            run_triple_gate(&i, &EvalGatePolicy::canonical()).unwrap_err(),
            TripleGateError::SnapshotMissing
        ));
        i.snapshot_taken = true;
        // No eval pass → fail
        assert!(matches!(
            run_triple_gate(&i, &EvalGatePolicy::canonical()).unwrap_err(),
            TripleGateError::EvalFailed(_)
        ));
        i.eval_last_pass_seconds_ago = Some(100);
        // Eval ok but no approval → fail
        assert!(matches!(
            run_triple_gate(&i, &EvalGatePolicy::canonical()).unwrap_err(),
            TripleGateError::OracleOrHumanRequired
        ));
        i.human_approved = true;
        // All three pass → ok
        run_triple_gate(&i, &EvalGatePolicy::canonical()).unwrap();
    }

    #[test]
    fn critical_risk_triggers_gate_even_with_read_only() {
        let mut i = input(SideEffectClass::ReadOnly, RiskClass::Critical);
        assert!(matches!(
            run_triple_gate(&i, &EvalGatePolicy::canonical()).unwrap_err(),
            TripleGateError::SnapshotMissing
        ));
        i.snapshot_taken = true;
        // ReadOnly has gate=None → eval auto-passes
        // No approval → fail
        assert!(matches!(
            run_triple_gate(&i, &EvalGatePolicy::canonical()).unwrap_err(),
            TripleGateError::OracleOrHumanRequired
        ));
        i.oracle_approved = true;
        run_triple_gate(&i, &EvalGatePolicy::canonical()).unwrap();
    }

    #[test]
    fn oracle_alone_satisfies_third_gate() {
        let i = TripleGateInput {
            side_effect: SideEffectClass::Persistent,
            risk: RiskClass::High,
            snapshot_taken: true,
            eval_last_pass_seconds_ago: Some(100),
            oracle_approved: true,
            human_approved: false,
        };
        run_triple_gate(&i, &EvalGatePolicy::canonical()).unwrap();
    }

    #[test]
    fn stale_eval_caught() {
        let i = TripleGateInput {
            side_effect: SideEffectClass::Persistent,
            risk: RiskClass::High,
            snapshot_taken: true,
            eval_last_pass_seconds_ago: Some(10_000),
            oracle_approved: true,
            human_approved: false,
        };
        assert!(matches!(
            run_triple_gate(&i, &EvalGatePolicy::canonical()).unwrap_err(),
            TripleGateError::EvalFailed(_)
        ));
    }

    #[test]
    fn requires_triple_gate_pure_function() {
        assert!(requires_triple_gate(
            SideEffectClass::Persistent,
            RiskClass::Low
        ));
        assert!(requires_triple_gate(
            SideEffectClass::ReadOnly,
            RiskClass::Critical
        ));
        assert!(!requires_triple_gate(
            SideEffectClass::FsWrite,
            RiskClass::Low
        ));
        assert!(!requires_triple_gate(
            SideEffectClass::ReadOnly,
            RiskClass::Medium
        ));
    }

    #[test]
    fn input_serde_roundtrip() {
        let i = input(SideEffectClass::Persistent, RiskClass::Critical);
        let j = serde_json::to_string(&i).unwrap();
        let back: TripleGateInput = serde_json::from_str(&j).unwrap();
        assert_eq!(i, back);
    }
}
