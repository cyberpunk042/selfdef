//! `selfdef-policy-feature-flag` — per-policy mode flags.
//!
//! Each policy_id has a Mode + rationale. Mode = Enabled (active),
//! DryRun (decisions emitted as observations only), Disabled (no
//! effect). History of mode changes kept bounded.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-policy mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Active.
    Enabled,
    /// Decisions emitted as observations only.
    DryRun,
    /// Completely off.
    Disabled,
}

/// One toggle event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToggleEvent {
    /// Policy id.
    pub policy_id: String,
    /// New mode.
    pub mode: Mode,
    /// At unix.
    pub at_unix: u64,
    /// Operator-supplied rationale (≤ 200 chars).
    pub rationale: String,
}

/// Registry state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyFeatureFlag {
    /// Schema version.
    pub schema_version: String,
    /// policy_id → mode.
    pub modes: BTreeMap<String, Mode>,
    /// Toggle history (bounded MRU).
    pub history: Vec<ToggleEvent>,
    /// Max history entries.
    pub max_history: u32,
}

/// Errors.
#[derive(Debug, Error)]
pub enum FlagError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty policy id.
    #[error("policy_id empty")]
    EmptyPolicyId,
    /// Empty rationale.
    #[error("rationale empty")]
    EmptyRationale,
    /// Rationale too long.
    #[error("rationale length {0} > 200")]
    RationaleTooLong(usize),
    /// max_history zero.
    #[error("max_history is zero")]
    MaxHistoryZero,
}

impl PolicyFeatureFlag {
    /// New.
    pub fn new(max_history: u32) -> Result<Self, FlagError> {
        if max_history == 0 {
            return Err(FlagError::MaxHistoryZero);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            modes: BTreeMap::new(),
            history: Vec::new(),
            max_history,
        })
    }

    /// Set mode for a policy.
    pub fn set_mode(
        &mut self,
        policy_id: &str,
        mode: Mode,
        at_unix: u64,
        rationale: &str,
    ) -> Result<(), FlagError> {
        if policy_id.is_empty() {
            return Err(FlagError::EmptyPolicyId);
        }
        if rationale.is_empty() {
            return Err(FlagError::EmptyRationale);
        }
        let n = rationale.chars().count();
        if n > 200 {
            return Err(FlagError::RationaleTooLong(n));
        }
        self.modes.insert(policy_id.into(), mode);
        self.history.push(ToggleEvent {
            policy_id: policy_id.into(),
            mode,
            at_unix,
            rationale: rationale.into(),
        });
        while self.history.len() as u32 > self.max_history {
            self.history.remove(0);
        }
        Ok(())
    }

    /// Evaluate current mode (Enabled if not set explicitly).
    pub fn evaluate(&self, policy_id: &str) -> Mode {
        self.modes.get(policy_id).copied().unwrap_or(Mode::Enabled)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), FlagError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(FlagError::SchemaMismatch);
        }
        if self.max_history == 0 {
            return Err(FlagError::MaxHistoryZero);
        }
        for e in &self.history {
            if e.policy_id.is_empty() {
                return Err(FlagError::EmptyPolicyId);
            }
            if e.rationale.is_empty() {
                return Err(FlagError::EmptyRationale);
            }
            let n = e.rationale.chars().count();
            if n > 200 {
                return Err(FlagError::RationaleTooLong(n));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_enabled() {
        let f = PolicyFeatureFlag::new(10).unwrap();
        assert_eq!(f.evaluate("some-policy"), Mode::Enabled);
    }

    #[test]
    fn set_mode_sticks() {
        let mut f = PolicyFeatureFlag::new(10).unwrap();
        f.set_mode("net-egress", Mode::DryRun, 100, "tuning")
            .unwrap();
        assert_eq!(f.evaluate("net-egress"), Mode::DryRun);
    }

    #[test]
    fn history_records_changes() {
        let mut f = PolicyFeatureFlag::new(10).unwrap();
        f.set_mode("a", Mode::Disabled, 100, "reason1").unwrap();
        f.set_mode("a", Mode::Enabled, 200, "reason2").unwrap();
        assert_eq!(f.history.len(), 2);
    }

    #[test]
    fn history_caps() {
        let mut f = PolicyFeatureFlag::new(2).unwrap();
        for i in 0..5 {
            f.set_mode("a", Mode::Enabled, i, &format!("r-{i}"))
                .unwrap();
        }
        assert_eq!(f.history.len(), 2);
    }

    #[test]
    fn empty_policy_rejected() {
        let mut f = PolicyFeatureFlag::new(10).unwrap();
        assert!(matches!(
            f.set_mode("", Mode::Enabled, 0, "r").unwrap_err(),
            FlagError::EmptyPolicyId
        ));
    }

    #[test]
    fn empty_rationale_rejected() {
        let mut f = PolicyFeatureFlag::new(10).unwrap();
        assert!(matches!(
            f.set_mode("p", Mode::Enabled, 0, "").unwrap_err(),
            FlagError::EmptyRationale
        ));
    }

    #[test]
    fn long_rationale_rejected() {
        let mut f = PolicyFeatureFlag::new(10).unwrap();
        let r = "x".repeat(201);
        assert!(matches!(
            f.set_mode("p", Mode::Enabled, 0, &r).unwrap_err(),
            FlagError::RationaleTooLong(201)
        ));
    }

    #[test]
    fn max_history_zero_rejected() {
        assert!(matches!(
            PolicyFeatureFlag::new(0).unwrap_err(),
            FlagError::MaxHistoryZero
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut f = PolicyFeatureFlag::new(10).unwrap();
        f.schema_version = "9.9.9".into();
        assert!(matches!(
            f.validate().unwrap_err(),
            FlagError::SchemaMismatch
        ));
    }

    #[test]
    fn mode_serde_kebab() {
        assert_eq!(serde_json::to_string(&Mode::DryRun).unwrap(), "\"dry-run\"");
    }

    #[test]
    fn flag_serde_roundtrip() {
        let mut f = PolicyFeatureFlag::new(10).unwrap();
        f.set_mode("p", Mode::Disabled, 100, "r").unwrap();
        let j = serde_json::to_string(&f).unwrap();
        let back: PolicyFeatureFlag = serde_json::from_str(&j).unwrap();
        assert_eq!(f, back);
    }
}
