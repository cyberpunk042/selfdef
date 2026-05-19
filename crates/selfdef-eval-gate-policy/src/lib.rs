//! `selfdef-eval-gate-policy` — IPS-side per-action eval gate.
//!
//! Some high-risk action classes (persistent commit, network egress,
//! process spawn) cannot proceed until an eval suite of a required
//! kind has passed within the configured staleness window. This crate
//! owns the policy mapping (SideEffectClass → required EvalGate).
//!
//! The runtime eval-suite-catalog mirrors approved gates; the daemon
//! refuses any action that requires a gate whose last-passed timestamp
//! is older than the staleness threshold.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_policy_decision::SideEffectClass;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// 5 canonical eval gate kinds (operator-curated names that match the
/// runtime eval-suite-catalog's `SuiteId` semantics — selfdef owns the
/// requirement, not the runtime catalog).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvalGate {
    /// No gate required.
    None,
    /// Smoke — fastest sanity.
    Smoke,
    /// Regression — full functional coverage.
    Regression,
    /// Safety — adversarial alignment scenarios.
    Safety,
    /// Pre-commit — operator-curated commit gate (subset of regression).
    PreCommit,
}

/// Per-side-effect requirement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateRequirement {
    /// Side-effect class.
    pub side_effect: SideEffectClass,
    /// Required gate (`None` means no eval required for this class).
    pub gate: EvalGate,
    /// Staleness window — seconds since last successful run.
    pub staleness_seconds: u32,
}

/// Policy envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvalGatePolicy {
    /// Schema version.
    pub schema_version: String,
    /// 6 requirements (one per SideEffectClass).
    pub requirements: Vec<GateRequirement>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum EvalGateError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 6.
    #[error("requirement count {0} != 6")]
    CountInvalid(usize),
    /// Missing.
    #[error("missing requirement for {0:?}")]
    Missing(SideEffectClass),
    /// Gate stale.
    #[error("gate {gate:?} for {side_effect:?} stale: last_pass_seconds_ago={age} > staleness={limit}")]
    Stale {
        /// side_effect.
        side_effect: SideEffectClass,
        /// gate.
        gate: EvalGate,
        /// age.
        age: u32,
        /// limit.
        limit: u32,
    },
    /// Gate never passed.
    #[error("gate {gate:?} for {side_effect:?} never passed")]
    NeverPassed {
        /// side_effect.
        side_effect: SideEffectClass,
        /// gate.
        gate: EvalGate,
    },
}

const REQUIRED: [SideEffectClass; 6] = [
    SideEffectClass::None, SideEffectClass::ReadOnly, SideEffectClass::FsWrite,
    SideEffectClass::NetworkEgress, SideEffectClass::Process, SideEffectClass::Persistent,
];

impl EvalGatePolicy {
    /// Canonical defaults.
    pub fn canonical() -> Self {
        let requirements = vec![
            GateRequirement { side_effect: SideEffectClass::None,          gate: EvalGate::None,       staleness_seconds: 0 },
            GateRequirement { side_effect: SideEffectClass::ReadOnly,      gate: EvalGate::None,       staleness_seconds: 0 },
            GateRequirement { side_effect: SideEffectClass::FsWrite,       gate: EvalGate::Smoke,      staleness_seconds: 3_600 },
            GateRequirement { side_effect: SideEffectClass::NetworkEgress, gate: EvalGate::Regression, staleness_seconds: 7_200 },
            GateRequirement { side_effect: SideEffectClass::Process,       gate: EvalGate::Safety,     staleness_seconds: 7_200 },
            GateRequirement { side_effect: SideEffectClass::Persistent,    gate: EvalGate::PreCommit,  staleness_seconds: 1_800 },
        ];
        Self {
            schema_version: SCHEMA_VERSION.into(),
            requirements,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), EvalGateError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(EvalGateError::SchemaMismatch);
        }
        if self.requirements.len() != 6 {
            return Err(EvalGateError::CountInvalid(self.requirements.len()));
        }
        for s in REQUIRED {
            if !self.requirements.iter().any(|r| r.side_effect == s) {
                return Err(EvalGateError::Missing(s));
            }
        }
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, s: SideEffectClass) -> Option<&GateRequirement> {
        self.requirements.iter().find(|r| r.side_effect == s)
    }

    /// IPS-authoritative admission check.
    ///
    /// `last_pass_seconds_ago` — `None` if gate has never passed.
    pub fn admit(
        &self,
        side_effect: SideEffectClass,
        last_pass_seconds_ago: Option<u32>,
    ) -> Result<(), EvalGateError> {
        let req = self.get(side_effect).ok_or(EvalGateError::Missing(side_effect))?;
        if req.gate == EvalGate::None { return Ok(()); }
        let age = last_pass_seconds_ago.ok_or(EvalGateError::NeverPassed {
            side_effect, gate: req.gate,
        })?;
        if age > req.staleness_seconds {
            return Err(EvalGateError::Stale {
                side_effect, gate: req.gate,
                age, limit: req.staleness_seconds,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        EvalGatePolicy::canonical().validate().unwrap();
    }

    #[test]
    fn none_and_read_only_no_gate() {
        let p = EvalGatePolicy::canonical();
        p.admit(SideEffectClass::None, None).unwrap();
        p.admit(SideEffectClass::ReadOnly, None).unwrap();
    }

    #[test]
    fn fs_write_requires_recent_smoke() {
        let p = EvalGatePolicy::canonical();
        // 100s ago — within 1h window
        p.admit(SideEffectClass::FsWrite, Some(100)).unwrap();
        // 10000s ago — stale
        assert!(matches!(
            p.admit(SideEffectClass::FsWrite, Some(10_000)).unwrap_err(),
            EvalGateError::Stale { .. }
        ));
        // Never passed
        assert!(matches!(
            p.admit(SideEffectClass::FsWrite, None).unwrap_err(),
            EvalGateError::NeverPassed { .. }
        ));
    }

    #[test]
    fn persistent_requires_pre_commit() {
        let p = EvalGatePolicy::canonical();
        let req = p.get(SideEffectClass::Persistent).unwrap();
        assert_eq!(req.gate, EvalGate::PreCommit);
        assert_eq!(req.staleness_seconds, 1_800);
    }

    #[test]
    fn process_requires_safety() {
        let p = EvalGatePolicy::canonical();
        let req = p.get(SideEffectClass::Process).unwrap();
        assert_eq!(req.gate, EvalGate::Safety);
    }

    #[test]
    fn network_requires_regression() {
        let p = EvalGatePolicy::canonical();
        let req = p.get(SideEffectClass::NetworkEgress).unwrap();
        assert_eq!(req.gate, EvalGate::Regression);
    }

    #[test]
    fn count_invalid_caught() {
        let mut p = EvalGatePolicy::canonical();
        p.requirements.pop();
        assert!(matches!(p.validate().unwrap_err(), EvalGateError::CountInvalid(5)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = EvalGatePolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), EvalGateError::SchemaMismatch));
    }

    #[test]
    fn gate_serde_kebab() {
        assert_eq!(serde_json::to_string(&EvalGate::Smoke).unwrap(), "\"smoke\"");
        assert_eq!(serde_json::to_string(&EvalGate::PreCommit).unwrap(), "\"pre-commit\"");
        assert_eq!(serde_json::to_string(&EvalGate::None).unwrap(), "\"none\"");
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = EvalGatePolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: EvalGatePolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
