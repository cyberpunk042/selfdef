//! `selfdef-llm-cost-tracker` — per-model spend ledger.
//!
//! Costs are tracked in **micro-units** (1/1_000_000 of a unit
//! currency) for integer precision. Each `record(model, usage)`
//! accrues per-tier and per-model totals where `Usage { input_tokens,
//! output_tokens, cache_read_tokens, cache_write_tokens }`. A per-
//! model `Rates { input_micros_per_1k, output_micros_per_1k,
//! cache_read_micros_per_1k, cache_write_micros_per_1k }` converts
//! tokens to micro-units.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Rates per 1k tokens (in micro-units).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rates {
    /// Input tokens.
    pub input_micros_per_1k: u64,
    /// Output tokens.
    pub output_micros_per_1k: u64,
    /// Cache read.
    pub cache_read_micros_per_1k: u64,
    /// Cache write.
    pub cache_write_micros_per_1k: u64,
}

/// Per-call usage.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Usage {
    /// Input.
    pub input_tokens: u64,
    /// Output.
    pub output_tokens: u64,
    /// Cache read.
    pub cache_read_tokens: u64,
    /// Cache write.
    pub cache_write_tokens: u64,
}

/// Per-tier breakdown.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TierTotals {
    /// Input micros.
    pub input_micros: u64,
    /// Output micros.
    pub output_micros: u64,
    /// Cache read micros.
    pub cache_read_micros: u64,
    /// Cache write micros.
    pub cache_write_micros: u64,
}

impl TierTotals {
    /// Total micros across tiers.
    pub fn total_micros(self) -> u64 {
        self.input_micros
            .saturating_add(self.output_micros)
            .saturating_add(self.cache_read_micros)
            .saturating_add(self.cache_write_micros)
    }
}

/// Per-model state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelState {
    /// Rates.
    pub rates: Rates,
    /// Aggregate tier totals.
    pub totals: TierTotals,
    /// Calls counted.
    pub calls: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LlmCostTracker {
    /// Schema version.
    pub schema_version: String,
    /// model → state.
    pub models: BTreeMap<String, ModelState>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CostError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty model.
    #[error("model id empty")]
    EmptyModel,
    /// Unknown.
    #[error("unknown model: {0}")]
    UnknownModel(String),
}

fn tokens_to_micros(tokens: u64, rate_per_1k: u64) -> u64 {
    // rate per 1k → multiply tokens × rate / 1000
    tokens.saturating_mul(rate_per_1k) / 1000
}

impl LlmCostTracker {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            models: BTreeMap::new(),
        }
    }

    /// Set rates (creates entry if missing).
    pub fn set_rates(&mut self, model: &str, rates: Rates) -> Result<(), CostError> {
        if model.is_empty() {
            return Err(CostError::EmptyModel);
        }
        let entry = self.models.entry(model.into()).or_insert(ModelState {
            rates,
            totals: TierTotals::default(),
            calls: 0,
        });
        entry.rates = rates;
        Ok(())
    }

    /// Record usage for an existing model.
    pub fn record(&mut self, model: &str, usage: Usage) -> Result<TierTotals, CostError> {
        if model.is_empty() {
            return Err(CostError::EmptyModel);
        }
        let m = self
            .models
            .get_mut(model)
            .ok_or_else(|| CostError::UnknownModel(model.into()))?;
        let delta = TierTotals {
            input_micros: tokens_to_micros(usage.input_tokens, m.rates.input_micros_per_1k),
            output_micros: tokens_to_micros(usage.output_tokens, m.rates.output_micros_per_1k),
            cache_read_micros: tokens_to_micros(
                usage.cache_read_tokens,
                m.rates.cache_read_micros_per_1k,
            ),
            cache_write_micros: tokens_to_micros(
                usage.cache_write_tokens,
                m.rates.cache_write_micros_per_1k,
            ),
        };
        m.totals.input_micros = m.totals.input_micros.saturating_add(delta.input_micros);
        m.totals.output_micros = m.totals.output_micros.saturating_add(delta.output_micros);
        m.totals.cache_read_micros = m
            .totals
            .cache_read_micros
            .saturating_add(delta.cache_read_micros);
        m.totals.cache_write_micros = m
            .totals
            .cache_write_micros
            .saturating_add(delta.cache_write_micros);
        m.calls = m.calls.saturating_add(1);
        Ok(delta)
    }

    /// Per-model totals snapshot.
    pub fn totals(&self, model: &str) -> Option<TierTotals> {
        self.models.get(model).map(|m| m.totals)
    }

    /// Sum across all models.
    pub fn grand_total_micros(&self) -> u64 {
        self.models
            .values()
            .map(|m| m.totals.total_micros())
            .fold(0u64, |a, b| a.saturating_add(b))
    }

    /// Reset all counters but keep rates.
    pub fn reset_totals(&mut self) {
        for m in self.models.values_mut() {
            m.totals = TierTotals::default();
            m.calls = 0;
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CostError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CostError::SchemaMismatch);
        }
        for k in self.models.keys() {
            if k.is_empty() {
                return Err(CostError::EmptyModel);
            }
        }
        Ok(())
    }
}

impl Default for LlmCostTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opus_rates() -> Rates {
        Rates {
            input_micros_per_1k: 15_000,
            output_micros_per_1k: 75_000,
            cache_read_micros_per_1k: 1_500,
            cache_write_micros_per_1k: 18_750,
        }
    }

    #[test]
    fn record_basic() {
        let mut t = LlmCostTracker::new();
        t.set_rates("opus", opus_rates()).unwrap();
        let d = t
            .record(
                "opus",
                Usage {
                    input_tokens: 1000,
                    output_tokens: 500,
                    ..Usage::default()
                },
            )
            .unwrap();
        // 1000 input × 15_000/1000 = 15_000 micros.
        assert_eq!(d.input_micros, 15_000);
        // 500 output × 75_000/1000 = 37_500.
        assert_eq!(d.output_micros, 37_500);
    }

    #[test]
    fn totals_accumulate() {
        let mut t = LlmCostTracker::new();
        t.set_rates("opus", opus_rates()).unwrap();
        t.record(
            "opus",
            Usage {
                input_tokens: 1000,
                ..Usage::default()
            },
        )
        .unwrap();
        t.record(
            "opus",
            Usage {
                input_tokens: 1000,
                ..Usage::default()
            },
        )
        .unwrap();
        assert_eq!(t.totals("opus").unwrap().input_micros, 30_000);
    }

    #[test]
    fn calls_count() {
        let mut t = LlmCostTracker::new();
        t.set_rates("opus", opus_rates()).unwrap();
        t.record("opus", Usage::default()).unwrap();
        t.record("opus", Usage::default()).unwrap();
        assert_eq!(t.models["opus"].calls, 2);
    }

    #[test]
    fn cache_tiers() {
        let mut t = LlmCostTracker::new();
        t.set_rates("opus", opus_rates()).unwrap();
        let d = t
            .record(
                "opus",
                Usage {
                    cache_read_tokens: 1000,
                    cache_write_tokens: 1000,
                    ..Usage::default()
                },
            )
            .unwrap();
        assert_eq!(d.cache_read_micros, 1_500);
        assert_eq!(d.cache_write_micros, 18_750);
    }

    #[test]
    fn grand_total_sums() {
        let mut t = LlmCostTracker::new();
        t.set_rates("opus", opus_rates()).unwrap();
        t.set_rates(
            "haiku",
            Rates {
                input_micros_per_1k: 800,
                output_micros_per_1k: 4_000,
                ..Rates::default()
            },
        )
        .unwrap();
        t.record(
            "opus",
            Usage {
                input_tokens: 1000,
                output_tokens: 500,
                ..Usage::default()
            },
        )
        .unwrap();
        t.record(
            "haiku",
            Usage {
                input_tokens: 1000,
                ..Usage::default()
            },
        )
        .unwrap();
        // opus: 15_000 + 37_500 = 52_500
        // haiku: 800
        assert_eq!(t.grand_total_micros(), 53_300);
    }

    #[test]
    fn reset_clears_totals_keeps_rates() {
        let mut t = LlmCostTracker::new();
        t.set_rates("opus", opus_rates()).unwrap();
        t.record(
            "opus",
            Usage {
                input_tokens: 1000,
                ..Usage::default()
            },
        )
        .unwrap();
        t.reset_totals();
        assert_eq!(t.totals("opus").unwrap().input_micros, 0);
        assert_eq!(t.models["opus"].calls, 0);
        // Rates preserved.
        assert_eq!(t.models["opus"].rates.input_micros_per_1k, 15_000);
    }

    #[test]
    fn unknown_model_rejected() {
        let mut t = LlmCostTracker::new();
        assert!(matches!(
            t.record("nope", Usage::default()).unwrap_err(),
            CostError::UnknownModel(_)
        ));
    }

    #[test]
    fn empty_model_rejected() {
        let mut t = LlmCostTracker::new();
        assert!(matches!(
            t.set_rates("", Rates::default()).unwrap_err(),
            CostError::EmptyModel
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = LlmCostTracker::new();
        t.schema_version = "9.9.9".into();
        assert!(matches!(
            t.validate().unwrap_err(),
            CostError::SchemaMismatch
        ));
    }

    #[test]
    fn cost_serde_roundtrip() {
        let mut t = LlmCostTracker::new();
        t.set_rates("opus", opus_rates()).unwrap();
        t.record(
            "opus",
            Usage {
                input_tokens: 1000,
                output_tokens: 500,
                ..Usage::default()
            },
        )
        .unwrap();
        let j = serde_json::to_string(&t).unwrap();
        let back: LlmCostTracker = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
