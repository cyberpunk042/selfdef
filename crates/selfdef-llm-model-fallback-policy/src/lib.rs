//! `selfdef-llm-model-fallback-policy` — primary/fallback chain.
//!
//! Each named chain has an ordered list of model ids. Per model:
//! consecutive failure count + a cooldown-until timestamp. `pick(
//! chain, now_ms)` returns the first model in the chain that is
//! either healthy or has cleared its cooldown. `record_failure(
//! chain, model, now_ms, cooldown_ms)` marks the model unhealthy
//! until `now_ms + cooldown_ms`. `record_success(chain, model)`
//! resets that model.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-model health.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelHealth {
    /// Consecutive failure count.
    pub fail_streak: u32,
    /// In cooldown until.
    pub cooldown_until_ms: u64,
    /// Total successes.
    pub total_success: u64,
    /// Total failures.
    pub total_failure: u64,
}

/// A named chain.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Chain {
    /// Ordered model ids.
    pub models: Vec<String>,
    /// Per-model health.
    pub health: BTreeMap<String, ModelHealth>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelFallbackPolicy {
    /// Schema version.
    pub schema_version: String,
    /// chain_id → chain.
    pub chains: BTreeMap<String, Chain>,
}

/// Pick verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PickVerdict {
    /// First healthy model.
    Picked {
        /// model id.
        model: String,
        /// position in chain (0-based).
        rank: u32,
    },
    /// All exhausted.
    AllInCooldown {
        /// soonest cooldown end across the chain.
        next_available_ms: u64,
    },
    /// Empty chain or unknown.
    NoModels,
}

/// Errors.
#[derive(Debug, Error)]
pub enum FallbackError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty chain id.
    #[error("chain id empty")]
    EmptyChain,
    /// Empty model id.
    #[error("model id empty")]
    EmptyModel,
    /// Unknown chain.
    #[error("unknown chain: {0}")]
    UnknownChain(String),
}

impl ModelFallbackPolicy {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            chains: BTreeMap::new(),
        }
    }

    /// Define a chain (overwrites existing).
    pub fn set_chain(&mut self, chain_id: &str, models: &[&str]) -> Result<(), FallbackError> {
        if chain_id.is_empty() { return Err(FallbackError::EmptyChain); }
        for m in models {
            if m.is_empty() { return Err(FallbackError::EmptyModel); }
        }
        let chain = Chain {
            models: models.iter().map(|s| (*s).into()).collect(),
            health: BTreeMap::new(),
        };
        self.chains.insert(chain_id.into(), chain);
        Ok(())
    }

    /// Pick the first usable model.
    pub fn pick(&self, chain_id: &str, now_ms: u64) -> PickVerdict {
        let Some(chain) = self.chains.get(chain_id) else { return PickVerdict::NoModels; };
        if chain.models.is_empty() { return PickVerdict::NoModels; }
        let mut soonest = u64::MAX;
        for (rank, m) in chain.models.iter().enumerate() {
            let h = chain.health.get(m);
            let cooldown_until = h.map(|h| h.cooldown_until_ms).unwrap_or(0);
            if now_ms >= cooldown_until {
                return PickVerdict::Picked { model: m.clone(), rank: rank as u32 };
            }
            if cooldown_until < soonest { soonest = cooldown_until; }
        }
        PickVerdict::AllInCooldown { next_available_ms: soonest }
    }

    /// Record a failure → place this model in cooldown.
    pub fn record_failure(&mut self, chain_id: &str, model: &str, now_ms: u64, cooldown_ms: u64) -> Result<(), FallbackError> {
        let chain = self.chains.get_mut(chain_id)
            .ok_or_else(|| FallbackError::UnknownChain(chain_id.into()))?;
        let h = chain.health.entry(model.into()).or_default();
        h.fail_streak = h.fail_streak.saturating_add(1);
        h.total_failure = h.total_failure.saturating_add(1);
        h.cooldown_until_ms = now_ms.saturating_add(cooldown_ms);
        Ok(())
    }

    /// Record a success → clear streak and cooldown.
    pub fn record_success(&mut self, chain_id: &str, model: &str) -> Result<(), FallbackError> {
        let chain = self.chains.get_mut(chain_id)
            .ok_or_else(|| FallbackError::UnknownChain(chain_id.into()))?;
        let h = chain.health.entry(model.into()).or_default();
        h.fail_streak = 0;
        h.cooldown_until_ms = 0;
        h.total_success = h.total_success.saturating_add(1);
        Ok(())
    }

    /// Health snapshot.
    pub fn health(&self, chain_id: &str, model: &str) -> Option<&ModelHealth> {
        self.chains.get(chain_id).and_then(|c| c.health.get(model))
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), FallbackError> {
        if self.schema_version != SCHEMA_VERSION { return Err(FallbackError::SchemaMismatch); }
        for (id, c) in &self.chains {
            if id.is_empty() { return Err(FallbackError::EmptyChain); }
            for m in &c.models {
                if m.is_empty() { return Err(FallbackError::EmptyModel); }
            }
        }
        Ok(())
    }
}

impl Default for ModelFallbackPolicy {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_first_when_all_healthy() {
        let mut p = ModelFallbackPolicy::new();
        p.set_chain("primary", &["sonnet", "haiku", "opus"]).unwrap();
        match p.pick("primary", 1000) {
            PickVerdict::Picked { model, rank } => {
                assert_eq!(model, "sonnet");
                assert_eq!(rank, 0);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn falls_back_after_failure() {
        let mut p = ModelFallbackPolicy::new();
        p.set_chain("primary", &["sonnet", "haiku"]).unwrap();
        p.record_failure("primary", "sonnet", 1000, 5000).unwrap();
        // Sonnet in cooldown until 6000.
        match p.pick("primary", 2000) {
            PickVerdict::Picked { model, rank } => {
                assert_eq!(model, "haiku");
                assert_eq!(rank, 1);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn cooldown_clears_with_time() {
        let mut p = ModelFallbackPolicy::new();
        p.set_chain("primary", &["sonnet"]).unwrap();
        p.record_failure("primary", "sonnet", 1000, 5000).unwrap();
        // After cooldown ends.
        match p.pick("primary", 7000) {
            PickVerdict::Picked { model, .. } => assert_eq!(model, "sonnet"),
            _ => panic!(),
        }
    }

    #[test]
    fn all_in_cooldown_returns_next_available() {
        let mut p = ModelFallbackPolicy::new();
        p.set_chain("primary", &["a", "b"]).unwrap();
        p.record_failure("primary", "a", 0, 1000).unwrap();
        p.record_failure("primary", "b", 0, 500).unwrap();
        match p.pick("primary", 100) {
            PickVerdict::AllInCooldown { next_available_ms } => {
                assert_eq!(next_available_ms, 500);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn success_clears_cooldown() {
        let mut p = ModelFallbackPolicy::new();
        p.set_chain("primary", &["a"]).unwrap();
        p.record_failure("primary", "a", 0, 10_000).unwrap();
        p.record_success("primary", "a").unwrap();
        match p.pick("primary", 100) {
            PickVerdict::Picked { model, .. } => assert_eq!(model, "a"),
            _ => panic!(),
        }
        assert_eq!(p.health("primary", "a").unwrap().fail_streak, 0);
    }

    #[test]
    fn unknown_chain_no_models() {
        let p = ModelFallbackPolicy::new();
        assert_eq!(p.pick("nope", 0), PickVerdict::NoModels);
    }

    #[test]
    fn empty_chain_no_models() {
        let mut p = ModelFallbackPolicy::new();
        p.set_chain("primary", &[]).unwrap();
        assert_eq!(p.pick("primary", 0), PickVerdict::NoModels);
    }

    #[test]
    fn fail_streak_accumulates() {
        let mut p = ModelFallbackPolicy::new();
        p.set_chain("primary", &["a"]).unwrap();
        p.record_failure("primary", "a", 0, 100).unwrap();
        p.record_failure("primary", "a", 200, 100).unwrap();
        assert_eq!(p.health("primary", "a").unwrap().fail_streak, 2);
        assert_eq!(p.health("primary", "a").unwrap().total_failure, 2);
    }

    #[test]
    fn empty_chain_id_rejected() {
        let mut p = ModelFallbackPolicy::new();
        assert!(matches!(p.set_chain("", &["a"]).unwrap_err(), FallbackError::EmptyChain));
    }

    #[test]
    fn empty_model_id_rejected() {
        let mut p = ModelFallbackPolicy::new();
        assert!(matches!(p.set_chain("c", &[""]).unwrap_err(), FallbackError::EmptyModel));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = ModelFallbackPolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), FallbackError::SchemaMismatch));
    }

    #[test]
    fn fallback_serde_roundtrip() {
        let mut p = ModelFallbackPolicy::new();
        p.set_chain("primary", &["a", "b"]).unwrap();
        p.record_failure("primary", "a", 0, 1000).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: ModelFallbackPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
