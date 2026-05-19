//! `selfdef-decision-router` — composite gate that returns the final Outcome.
//!
//! Runs the gates in canonical order:
//! 1. Trust floor (against trust score)
//! 2. (Caller's eval-gate hint pre-evaluated)
//! 3. Sandbox-tier escalation (caller-supplied flag)
//!
//! Returns `(Outcome, decided_by)` where decided_by indicates which
//! gate produced the final answer.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_policy_decision::{Outcome, SideEffectClass};
use selfdef_trust_floor::TrustFloorManifest;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Inputs to the router.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouterInput {
    /// Side-effect class.
    pub side_effect: SideEffectClass,
    /// Subject trust score 0..=100.
    pub trust_score: u8,
    /// Eval-gate pre-evaluated decision (caller passes None to skip).
    pub eval_gate_passes: Option<bool>,
    /// Operator requested sandbox escalation.
    pub sandbox_requested: bool,
    /// Operator approval flag.
    pub operator_approved: bool,
}

/// Which gate decided the final outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecidedBy {
    /// Trust floor below threshold.
    TrustFloor,
    /// Eval gate failed.
    EvalGate,
    /// Operator requested sandbox.
    Sandbox,
    /// All gates cleared.
    AllGatesCleared,
}

/// Router output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouterOutput {
    /// Final outcome.
    pub outcome: Outcome,
    /// Which gate decided.
    pub decided_by: DecidedBy,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RouterError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Trust score out of range.
    #[error("trust_score {0} > 100")]
    TrustOutOfRange(u8),
}

/// Run the router.
pub fn route(
    input: &RouterInput,
    floor: &TrustFloorManifest,
) -> Result<RouterOutput, RouterError> {
    if input.trust_score > 100 {
        return Err(RouterError::TrustOutOfRange(input.trust_score));
    }
    // 1. Trust floor → Allow / Ask / Deny.
    let trust_outcome = floor.decide_outcome(input.side_effect, input.trust_score)
        .unwrap_or(Outcome::Deny);
    if trust_outcome == Outcome::Deny {
        return Ok(RouterOutput { outcome: Outcome::Deny, decided_by: DecidedBy::TrustFloor });
    }
    if trust_outcome == Outcome::Ask && !input.operator_approved {
        return Ok(RouterOutput { outcome: Outcome::Ask, decided_by: DecidedBy::TrustFloor });
    }
    // 2. Eval gate.
    if let Some(false) = input.eval_gate_passes {
        return Ok(RouterOutput { outcome: Outcome::Deny, decided_by: DecidedBy::EvalGate });
    }
    // 3. Sandbox escalation.
    if input.sandbox_requested {
        return Ok(RouterOutput { outcome: Outcome::Sandbox, decided_by: DecidedBy::Sandbox });
    }
    Ok(RouterOutput { outcome: Outcome::Allow, decided_by: DecidedBy::AllGatesCleared })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(sec: SideEffectClass, trust: u8) -> RouterInput {
        RouterInput {
            side_effect: sec,
            trust_score: trust,
            eval_gate_passes: None,
            sandbox_requested: false,
            operator_approved: false,
        }
    }

    #[test]
    fn high_trust_allows() {
        let r = route(&input(SideEffectClass::FsWrite, 90), &TrustFloorManifest::canonical()).unwrap();
        assert_eq!(r.outcome, Outcome::Allow);
        assert_eq!(r.decided_by, DecidedBy::AllGatesCleared);
    }

    #[test]
    fn low_trust_below_floor_denies() {
        let r = route(&input(SideEffectClass::FsWrite, 5), &TrustFloorManifest::canonical()).unwrap();
        assert_eq!(r.outcome, Outcome::Deny);
        assert_eq!(r.decided_by, DecidedBy::TrustFloor);
    }

    #[test]
    fn trust_in_ask_band_returns_ask() {
        let r = route(&input(SideEffectClass::FsWrite, 35), &TrustFloorManifest::canonical()).unwrap();
        assert_eq!(r.outcome, Outcome::Ask);
        assert_eq!(r.decided_by, DecidedBy::TrustFloor);
    }

    #[test]
    fn approval_promotes_ask_to_allow_path() {
        let mut i = input(SideEffectClass::FsWrite, 35);
        i.operator_approved = true;
        let r = route(&i, &TrustFloorManifest::canonical()).unwrap();
        assert_eq!(r.outcome, Outcome::Allow);
    }

    #[test]
    fn eval_gate_fails_denies() {
        let mut i = input(SideEffectClass::FsWrite, 90);
        i.eval_gate_passes = Some(false);
        let r = route(&i, &TrustFloorManifest::canonical()).unwrap();
        assert_eq!(r.outcome, Outcome::Deny);
        assert_eq!(r.decided_by, DecidedBy::EvalGate);
    }

    #[test]
    fn sandbox_requested_returns_sandbox() {
        let mut i = input(SideEffectClass::FsWrite, 90);
        i.sandbox_requested = true;
        let r = route(&i, &TrustFloorManifest::canonical()).unwrap();
        assert_eq!(r.outcome, Outcome::Sandbox);
        assert_eq!(r.decided_by, DecidedBy::Sandbox);
    }

    #[test]
    fn trust_out_of_range_caught() {
        assert!(matches!(
            route(&input(SideEffectClass::FsWrite, 150), &TrustFloorManifest::canonical()).unwrap_err(),
            RouterError::TrustOutOfRange(150)
        ));
    }

    #[test]
    fn decided_by_serde_kebab() {
        assert_eq!(serde_json::to_string(&DecidedBy::TrustFloor).unwrap(), "\"trust-floor\"");
        assert_eq!(serde_json::to_string(&DecidedBy::EvalGate).unwrap(), "\"eval-gate\"");
        assert_eq!(serde_json::to_string(&DecidedBy::AllGatesCleared).unwrap(), "\"all-gates-cleared\"");
    }

    #[test]
    fn output_serde_roundtrip() {
        let r = route(&input(SideEffectClass::FsWrite, 90), &TrustFloorManifest::canonical()).unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: RouterOutput = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
