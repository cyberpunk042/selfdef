//! `selfdef-policy-rollout-stage` — staged-rollout selector.
//!
//! Each policy_id has a `Stage`:
//!
//!   * `Disabled` — InScope always false.
//!   * `Canary { percent_ppm }` — InScope when `actor_hash mod
//!     1_000_000 < percent_ppm`.
//!   * `Beta { percent_ppm }` — same logic, semantically wider.
//!   * `Stable` — InScope always true.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Stage {
    /// Disabled.
    Disabled,
    /// Canary band.
    Canary {
        /// percent ppm (0..=1_000_000).
        percent_ppm: u32,
    },
    /// Beta band.
    Beta {
        /// percent ppm (0..=1_000_000).
        percent_ppm: u32,
    },
    /// Stable.
    Stable,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRolloutStage {
    /// Schema version.
    pub schema_version: String,
    /// policy_id → stage.
    pub stages: BTreeMap<String, Stage>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ScopeVerdict {
    /// Actor falls within the staged rollout.
    InScope,
    /// Actor is out of scope.
    OutOfScope,
    /// Policy not registered.
    Unknown,
}

/// Errors.
#[derive(Debug, Error)]
pub enum StageError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("policy id empty")]
    EmptyId,
    /// Percent over 1_000_000.
    #[error("percent_ppm {0} > 1_000_000")]
    PpmOver(u32),
}

impl PolicyRolloutStage {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            stages: BTreeMap::new(),
        }
    }

    /// Set stage.
    pub fn set(&mut self, policy_id: &str, stage: Stage) -> Result<(), StageError> {
        if policy_id.is_empty() {
            return Err(StageError::EmptyId);
        }
        if let Stage::Canary { percent_ppm } | Stage::Beta { percent_ppm } = &stage {
            if *percent_ppm > 1_000_000 {
                return Err(StageError::PpmOver(*percent_ppm));
            }
        }
        self.stages.insert(policy_id.into(), stage);
        Ok(())
    }

    /// Classify.
    pub fn classify(&self, policy_id: &str, actor_hash: u64) -> ScopeVerdict {
        let stage = match self.stages.get(policy_id) {
            Some(s) => *s,
            None => return ScopeVerdict::Unknown,
        };
        let bucket = (actor_hash % 1_000_000) as u32;
        match stage {
            Stage::Disabled => ScopeVerdict::OutOfScope,
            Stage::Stable => ScopeVerdict::InScope,
            Stage::Canary { percent_ppm } | Stage::Beta { percent_ppm } => {
                if bucket < percent_ppm {
                    ScopeVerdict::InScope
                } else {
                    ScopeVerdict::OutOfScope
                }
            }
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), StageError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(StageError::SchemaMismatch);
        }
        for (id, s) in &self.stages {
            if id.is_empty() {
                return Err(StageError::EmptyId);
            }
            if let Stage::Canary { percent_ppm } | Stage::Beta { percent_ppm } = s {
                if *percent_ppm > 1_000_000 {
                    return Err(StageError::PpmOver(*percent_ppm));
                }
            }
        }
        Ok(())
    }
}

impl Default for PolicyRolloutStage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_policy() {
        let p = PolicyRolloutStage::new();
        assert_eq!(p.classify("x", 0), ScopeVerdict::Unknown);
    }

    #[test]
    fn disabled_always_out() {
        let mut p = PolicyRolloutStage::new();
        p.set("x", Stage::Disabled).unwrap();
        assert_eq!(p.classify("x", 0), ScopeVerdict::OutOfScope);
        assert_eq!(p.classify("x", 999_999), ScopeVerdict::OutOfScope);
    }

    #[test]
    fn stable_always_in() {
        let mut p = PolicyRolloutStage::new();
        p.set("x", Stage::Stable).unwrap();
        assert_eq!(p.classify("x", 0), ScopeVerdict::InScope);
        assert_eq!(p.classify("x", 12_345_678), ScopeVerdict::InScope);
    }

    #[test]
    fn canary_band_includes_lower_bucket() {
        let mut p = PolicyRolloutStage::new();
        p.set(
            "x",
            Stage::Canary {
                percent_ppm: 10_000,
            },
        )
        .unwrap(); // 1.0%.
        assert_eq!(p.classify("x", 5_000), ScopeVerdict::InScope);
        assert_eq!(p.classify("x", 50_000), ScopeVerdict::OutOfScope);
    }

    #[test]
    fn beta_wider() {
        let mut p = PolicyRolloutStage::new();
        p.set(
            "x",
            Stage::Beta {
                percent_ppm: 500_000,
            },
        )
        .unwrap(); // 50%.
        assert_eq!(p.classify("x", 100_000), ScopeVerdict::InScope);
        assert_eq!(p.classify("x", 700_000), ScopeVerdict::OutOfScope);
    }

    #[test]
    fn ppm_over_rejected() {
        let mut p = PolicyRolloutStage::new();
        assert!(matches!(
            p.set(
                "x",
                Stage::Canary {
                    percent_ppm: 2_000_000
                }
            )
            .unwrap_err(),
            StageError::PpmOver(_)
        ));
    }

    #[test]
    fn empty_id_rejected() {
        let mut p = PolicyRolloutStage::new();
        assert!(matches!(
            p.set("", Stage::Stable).unwrap_err(),
            StageError::EmptyId
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = PolicyRolloutStage::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            StageError::SchemaMismatch
        ));
    }

    #[test]
    fn stage_serde_roundtrip() {
        let mut p = PolicyRolloutStage::new();
        p.set(
            "x",
            Stage::Canary {
                percent_ppm: 50_000,
            },
        )
        .unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: PolicyRolloutStage = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
