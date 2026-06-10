//! `selfdef-periodic-quota-budget` — per-period quota.
//!
//! Each actor has a `cap_per_period`, current `consumed`, and
//! `current_period_start_ms`. `charge(actor, units, now)` resets
//! `consumed=0` if a new period began (current_period_start_ms +
//! period_ms <= now), then checks `consumed + units <= cap`. On
//! pass, increments; on fail, returns `Exceeded { available, requested }`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-actor state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorBudget {
    /// Cap per period.
    pub cap_per_period: u64,
    /// Consumed in current period.
    pub consumed: u64,
    /// Current period start.
    pub current_period_start_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeriodicQuotaBudget {
    /// Schema version.
    pub schema_version: String,
    /// Period length.
    pub period_ms: u64,
    /// actor → budget.
    pub actors: BTreeMap<String, ActorBudget>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ChargeVerdict {
    /// Accepted.
    Accepted,
    /// Exceeded.
    Exceeded {
        /// available now.
        available: u64,
        /// requested.
        requested: u64,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum BudgetError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("actor empty")]
    EmptyActor,
    /// Zero period.
    #[error("period must be > 0")]
    ZeroPeriod,
    /// Unknown.
    #[error("unknown actor: {0}")]
    UnknownActor(String),
}

impl PeriodicQuotaBudget {
    /// New.
    pub fn new(period_ms: u64) -> Result<Self, BudgetError> {
        if period_ms == 0 {
            return Err(BudgetError::ZeroPeriod);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            period_ms,
            actors: BTreeMap::new(),
        })
    }

    /// Set cap (creates entry with consumed=0).
    pub fn set_cap(
        &mut self,
        actor: &str,
        cap_per_period: u64,
        now_ms: u64,
    ) -> Result<(), BudgetError> {
        if actor.is_empty() {
            return Err(BudgetError::EmptyActor);
        }
        let entry = self.actors.entry(actor.into()).or_insert(ActorBudget {
            cap_per_period,
            consumed: 0,
            current_period_start_ms: now_ms,
        });
        entry.cap_per_period = cap_per_period;
        Ok(())
    }

    #[allow(dead_code)]
    fn maybe_roll(&self, b: &mut ActorBudget, now_ms: u64) {
        // Defend against a zero period (serde bypasses new()/validate()): with
        // period_ms==0 the `>= self.period_ms` check is always true and the
        // `elapsed / self.period_ms` below would divide by zero — a panic in
        // debug. Skip the roll; the budget never resets (fail-CLOSED: an
        // exhausted budget keeps denying) rather than crashing.
        if self.period_ms == 0 {
            return;
        }
        if now_ms.saturating_sub(b.current_period_start_ms) >= self.period_ms {
            // Snap forward by whole periods.
            let elapsed = now_ms.saturating_sub(b.current_period_start_ms);
            let periods = elapsed / self.period_ms;
            b.current_period_start_ms = b
                .current_period_start_ms
                .saturating_add(periods.saturating_mul(self.period_ms));
            b.consumed = 0;
        }
    }

    /// Charge.
    pub fn charge(
        &mut self,
        actor: &str,
        units: u64,
        now_ms: u64,
    ) -> Result<ChargeVerdict, BudgetError> {
        let period_ms = self.period_ms;
        let b = self
            .actors
            .get_mut(actor)
            .ok_or_else(|| BudgetError::UnknownActor(actor.into()))?;
        // Inline roll (avoid double borrow).
        if now_ms.saturating_sub(b.current_period_start_ms) >= period_ms {
            let elapsed = now_ms.saturating_sub(b.current_period_start_ms);
            let periods = elapsed / period_ms;
            b.current_period_start_ms = b
                .current_period_start_ms
                .saturating_add(periods.saturating_mul(period_ms));
            b.consumed = 0;
        }
        let available = b.cap_per_period.saturating_sub(b.consumed);
        if units > available {
            return Ok(ChargeVerdict::Exceeded {
                available,
                requested: units,
            });
        }
        b.consumed = b.consumed.saturating_add(units);
        Ok(ChargeVerdict::Accepted)
    }

    /// Remaining for actor at now.
    pub fn remaining(&mut self, actor: &str, now_ms: u64) -> Option<u64> {
        let period_ms = self.period_ms;
        let b = self.actors.get_mut(actor)?;
        if now_ms.saturating_sub(b.current_period_start_ms) >= period_ms {
            let elapsed = now_ms.saturating_sub(b.current_period_start_ms);
            let periods = elapsed / period_ms;
            b.current_period_start_ms = b
                .current_period_start_ms
                .saturating_add(periods.saturating_mul(period_ms));
            b.consumed = 0;
        }
        Some(b.cap_per_period.saturating_sub(b.consumed))
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BudgetError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BudgetError::SchemaMismatch);
        }
        if self.period_ms == 0 {
            return Err(BudgetError::ZeroPeriod);
        }
        for k in self.actors.keys() {
            if k.is_empty() {
                return Err(BudgetError::EmptyActor);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_cap_accepted() {
        let mut b = PeriodicQuotaBudget::new(1000).unwrap();
        b.set_cap("a", 100, 0).unwrap();
        assert_eq!(b.charge("a", 50, 100).unwrap(), ChargeVerdict::Accepted);
    }

    #[test]
    fn over_cap_exceeded() {
        let mut b = PeriodicQuotaBudget::new(1000).unwrap();
        b.set_cap("a", 100, 0).unwrap();
        b.charge("a", 100, 0).unwrap();
        match b.charge("a", 50, 100).unwrap() {
            ChargeVerdict::Exceeded {
                available,
                requested,
            } => {
                assert_eq!(available, 0);
                assert_eq!(requested, 50);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn period_rolls() {
        let mut b = PeriodicQuotaBudget::new(1000).unwrap();
        b.set_cap("a", 100, 0).unwrap();
        b.charge("a", 100, 0).unwrap();
        // After period (>= 1000ms), new period starts.
        assert_eq!(b.charge("a", 50, 1500).unwrap(), ChargeVerdict::Accepted);
    }

    #[test]
    fn multiple_periods_snap_forward() {
        let mut b = PeriodicQuotaBudget::new(1000).unwrap();
        b.set_cap("a", 100, 0).unwrap();
        b.charge("a", 100, 0).unwrap();
        // 5 periods later, should reset cleanly.
        assert_eq!(b.charge("a", 100, 5000).unwrap(), ChargeVerdict::Accepted);
    }

    #[test]
    fn remaining_reflects_consumption() {
        let mut b = PeriodicQuotaBudget::new(1000).unwrap();
        b.set_cap("a", 100, 0).unwrap();
        b.charge("a", 30, 0).unwrap();
        assert_eq!(b.remaining("a", 100), Some(70));
    }

    #[test]
    fn unknown_actor_rejected() {
        let mut b = PeriodicQuotaBudget::new(1000).unwrap();
        assert!(matches!(
            b.charge("nope", 1, 0).unwrap_err(),
            BudgetError::UnknownActor(_)
        ));
    }

    #[test]
    fn zero_period_rejected() {
        assert!(matches!(
            PeriodicQuotaBudget::new(0).unwrap_err(),
            BudgetError::ZeroPeriod
        ));
    }

    #[test]
    fn empty_actor_rejected() {
        let mut b = PeriodicQuotaBudget::new(1000).unwrap();
        assert!(matches!(
            b.set_cap("", 100, 0).unwrap_err(),
            BudgetError::EmptyActor
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut b = PeriodicQuotaBudget::new(1000).unwrap();
        b.schema_version = "9.9.9".into();
        assert!(matches!(
            b.validate().unwrap_err(),
            BudgetError::SchemaMismatch
        ));
    }

    #[test]
    fn budget_serde_roundtrip() {
        let mut b = PeriodicQuotaBudget::new(1000).unwrap();
        b.set_cap("a", 100, 0).unwrap();
        b.charge("a", 30, 0).unwrap();
        let j = serde_json::to_string(&b).unwrap();
        let back: PeriodicQuotaBudget = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
