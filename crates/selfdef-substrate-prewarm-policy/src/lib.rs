//! `selfdef-substrate-prewarm-policy` — per-Profile prewarm schedule.
//!
//! Each Profile carries an ordered `Vec<PrewarmStep>`. `plan(profile)`
//! returns the steps; the bootstrapper executes them in order,
//! respecting per-step `budget_ms` and the `optional` flag (failed
//! optional steps don't block bootstrap).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// Private.
    Private,
    /// Fast.
    Fast,
    /// Careful.
    Careful,
    /// Autonomous.
    Autonomous,
    /// Experimental.
    Experimental,
    /// Production.
    Production,
}

/// Step kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StepKind {
    /// Load model weights into RAM.
    LoadModelWeights,
    /// Prime GPU context.
    PrimeGpuContext,
    /// Warm KV cache with a stub prompt.
    WarmKvCache,
    /// Refresh embedding cache.
    RefreshEmbeddingCache,
    /// Pre-resolve DNS for outbound endpoints.
    PreresolveDns,
    /// Connect to event bus.
    ConnectEventBus,
}

/// One step.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrewarmStep {
    /// kind.
    pub kind: StepKind,
    /// per-step budget in ms.
    pub budget_ms: u64,
    /// failed optional steps don't block bootstrap.
    pub optional: bool,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubstratePrewarmPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Per-profile schedule.
    pub schedules: BTreeMap<Profile, Vec<PrewarmStep>>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum PrewarmError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Budget zero.
    #[error("step budget_ms must be > 0")]
    BudgetZero,
}

impl SubstratePrewarmPolicy {
    /// Canonical defaults.
    pub fn canonical() -> Self {
        let private = vec![
            PrewarmStep { kind: StepKind::LoadModelWeights, budget_ms: 5_000, optional: false },
            PrewarmStep { kind: StepKind::ConnectEventBus, budget_ms: 1_000, optional: false },
        ];
        let production = vec![
            PrewarmStep { kind: StepKind::LoadModelWeights, budget_ms: 5_000, optional: false },
            PrewarmStep { kind: StepKind::PrimeGpuContext, budget_ms: 4_000, optional: false },
            PrewarmStep { kind: StepKind::WarmKvCache, budget_ms: 2_000, optional: false },
            PrewarmStep { kind: StepKind::PreresolveDns, budget_ms: 1_500, optional: true },
            PrewarmStep { kind: StepKind::ConnectEventBus, budget_ms: 1_000, optional: false },
        ];
        let fast = vec![
            PrewarmStep { kind: StepKind::LoadModelWeights, budget_ms: 3_000, optional: false },
            PrewarmStep { kind: StepKind::PrimeGpuContext, budget_ms: 2_000, optional: true },
            PrewarmStep { kind: StepKind::ConnectEventBus, budget_ms: 1_000, optional: false },
        ];
        let careful = production.clone();
        let autonomous = production.clone();
        let experimental = vec![
            PrewarmStep { kind: StepKind::LoadModelWeights, budget_ms: 10_000, optional: false },
            PrewarmStep { kind: StepKind::PrimeGpuContext, budget_ms: 8_000, optional: true },
            PrewarmStep { kind: StepKind::WarmKvCache, budget_ms: 4_000, optional: true },
            PrewarmStep { kind: StepKind::RefreshEmbeddingCache, budget_ms: 3_000, optional: true },
            PrewarmStep { kind: StepKind::PreresolveDns, budget_ms: 2_000, optional: true },
            PrewarmStep { kind: StepKind::ConnectEventBus, budget_ms: 1_500, optional: false },
        ];

        let mut s = BTreeMap::new();
        s.insert(Profile::Private, private);
        s.insert(Profile::Fast, fast);
        s.insert(Profile::Careful, careful);
        s.insert(Profile::Autonomous, autonomous);
        s.insert(Profile::Experimental, experimental);
        s.insert(Profile::Production, production);
        Self {
            schema_version: SCHEMA_VERSION.into(),
            schedules: s,
        }
    }

    /// Plan.
    pub fn plan(&self, profile: Profile) -> Vec<PrewarmStep> {
        self.schedules.get(&profile).cloned().unwrap_or_default()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), PrewarmError> {
        if self.schema_version != SCHEMA_VERSION { return Err(PrewarmError::SchemaMismatch); }
        for steps in self.schedules.values() {
            for s in steps {
                if s.budget_ms == 0 { return Err(PrewarmError::BudgetZero); }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        SubstratePrewarmPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn plan_returns_steps() {
        let p = SubstratePrewarmPolicy::canonical();
        let plan = p.plan(Profile::Production);
        assert!(!plan.is_empty());
        assert_eq!(plan[0].kind, StepKind::LoadModelWeights);
    }

    #[test]
    fn unknown_profile_empty() {
        let mut p = SubstratePrewarmPolicy::canonical();
        p.schedules.clear();
        assert!(p.plan(Profile::Production).is_empty());
    }

    #[test]
    fn experimental_is_longest() {
        let p = SubstratePrewarmPolicy::canonical();
        let exp_len = p.plan(Profile::Experimental).len();
        let prod_len = p.plan(Profile::Production).len();
        let priv_len = p.plan(Profile::Private).len();
        assert!(exp_len >= prod_len);
        assert!(priv_len < prod_len);
    }

    #[test]
    fn dns_step_is_optional_everywhere() {
        let p = SubstratePrewarmPolicy::canonical();
        for prof in [Profile::Production, Profile::Experimental, Profile::Autonomous] {
            for step in p.plan(prof) {
                if step.kind == StepKind::PreresolveDns {
                    assert!(step.optional);
                }
            }
        }
    }

    #[test]
    fn budget_zero_rejected_on_validate() {
        let mut p = SubstratePrewarmPolicy::canonical();
        p.schedules.insert(Profile::Production, vec![
            PrewarmStep { kind: StepKind::LoadModelWeights, budget_ms: 0, optional: false },
        ]);
        assert!(matches!(p.validate().unwrap_err(), PrewarmError::BudgetZero));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = SubstratePrewarmPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), PrewarmError::SchemaMismatch));
    }

    #[test]
    fn prewarm_serde_roundtrip() {
        let p = SubstratePrewarmPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: SubstratePrewarmPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
