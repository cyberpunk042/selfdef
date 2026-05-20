//! `selfdef-policy-shadow-mode` — Off / Shadow / Enforce per policy.
//!
//! Each policy_id is registered with a `Mode`:
//!
//!   * `Off` — policy is dormant; classify_apply always returns Allow.
//!   * `Shadow` — policy decides but does not enforce. classify_apply
//!     returns Allow even when would_block=true, with a flag asking
//!     the audit recorder to log it as a shadow-block event.
//!   * `Enforce` — policy decides and enforces. classify_apply
//!     returns Block when would_block=true.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Dormant.
    Off,
    /// Decide but don't enforce.
    Shadow,
    /// Decide + enforce.
    Enforce,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyShadowMode {
    /// Schema version.
    pub schema_version: String,
    /// policy_id → mode.
    pub modes: BTreeMap<String, Mode>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ApplyVerdict {
    /// Allow without recording.
    Allow,
    /// Block (Enforce mode + would_block).
    Block,
    /// Allow but record as shadow-block.
    ShadowBlock,
    /// Policy not registered.
    Unconfigured,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ShadowError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty policy id.
    #[error("policy id empty")]
    EmptyId,
}

impl PolicyShadowMode {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            modes: BTreeMap::new(),
        }
    }

    /// Set the mode for a policy.
    pub fn set(&mut self, policy_id: &str, mode: Mode) -> Result<(), ShadowError> {
        if policy_id.is_empty() { return Err(ShadowError::EmptyId); }
        self.modes.insert(policy_id.into(), mode);
        Ok(())
    }

    /// Classify an apply.
    pub fn classify_apply(&self, policy_id: &str, would_block: bool) -> ApplyVerdict {
        let mode = match self.modes.get(policy_id) {
            Some(&m) => m,
            None => return ApplyVerdict::Unconfigured,
        };
        match (mode, would_block) {
            (Mode::Off, _) => ApplyVerdict::Allow,
            (Mode::Shadow, false) => ApplyVerdict::Allow,
            (Mode::Shadow, true) => ApplyVerdict::ShadowBlock,
            (Mode::Enforce, false) => ApplyVerdict::Allow,
            (Mode::Enforce, true) => ApplyVerdict::Block,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ShadowError> {
        if self.schema_version != SCHEMA_VERSION { return Err(ShadowError::SchemaMismatch); }
        for k in self.modes.keys() {
            if k.is_empty() { return Err(ShadowError::EmptyId); }
        }
        Ok(())
    }
}

impl Default for PolicyShadowMode {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unconfigured_unknown() {
        let p = PolicyShadowMode::new();
        assert_eq!(p.classify_apply("x", true), ApplyVerdict::Unconfigured);
    }

    #[test]
    fn off_always_allows() {
        let mut p = PolicyShadowMode::new();
        p.set("x", Mode::Off).unwrap();
        assert_eq!(p.classify_apply("x", true), ApplyVerdict::Allow);
    }

    #[test]
    fn shadow_block_when_would_block() {
        let mut p = PolicyShadowMode::new();
        p.set("x", Mode::Shadow).unwrap();
        assert_eq!(p.classify_apply("x", true), ApplyVerdict::ShadowBlock);
        assert_eq!(p.classify_apply("x", false), ApplyVerdict::Allow);
    }

    #[test]
    fn enforce_blocks_when_would_block() {
        let mut p = PolicyShadowMode::new();
        p.set("x", Mode::Enforce).unwrap();
        assert_eq!(p.classify_apply("x", true), ApplyVerdict::Block);
        assert_eq!(p.classify_apply("x", false), ApplyVerdict::Allow);
    }

    #[test]
    fn empty_id_rejected() {
        let mut p = PolicyShadowMode::new();
        assert!(matches!(p.set("", Mode::Enforce).unwrap_err(), ShadowError::EmptyId));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = PolicyShadowMode::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), ShadowError::SchemaMismatch));
    }

    #[test]
    fn shadow_serde_roundtrip() {
        let mut p = PolicyShadowMode::new();
        p.set("x", Mode::Shadow).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: PolicyShadowMode = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
