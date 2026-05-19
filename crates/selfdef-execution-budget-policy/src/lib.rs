//! `selfdef-execution-budget-policy` — per-action budget authority.
//!
//! Each action carries a triple cap (wall_seconds, tokens,
//! dollars_micro). An accumulator records what has already been
//! consumed; `admit(spend)` checks projected total ≤ cap on every
//! axis. When exhaustion happens the deny reports which dimension
//! ran out.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Which dimension exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExhaustionAxis {
    /// Wall seconds.
    Time,
    /// Tokens.
    Tokens,
    /// Dollars (1e-6).
    Cost,
}

/// A spend.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Spend {
    /// Wall seconds.
    pub wall_seconds: u64,
    /// Tokens.
    pub tokens: u64,
    /// Cost in micro-dollars.
    pub dollars_micro: u64,
}

impl Spend {
    /// Zero.
    pub const ZERO: Self = Self { wall_seconds: 0, tokens: 0, dollars_micro: 0 };

    /// Saturating add.
    pub fn add(self, other: Spend) -> Spend {
        Spend {
            wall_seconds: self.wall_seconds.saturating_add(other.wall_seconds),
            tokens: self.tokens.saturating_add(other.tokens),
            dollars_micro: self.dollars_micro.saturating_add(other.dollars_micro),
        }
    }
}

/// The cap.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct BudgetCap {
    /// Max wall seconds.
    pub max_wall_seconds: u64,
    /// Max tokens.
    pub max_tokens: u64,
    /// Max cost (micro-dollars).
    pub max_dollars_micro: u64,
}

/// Decision returned by admit().
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AdmitDecision {
    /// Admitted; new total recorded in `total`.
    Admit {
        /// total.
        total: Spend,
    },
    /// Denied; axis tells which dimension exhausted.
    Deny {
        /// axis.
        axis: ExhaustionAxis,
        /// would-be projected total.
        projected: Spend,
        /// cap that was exceeded.
        cap: BudgetCap,
    },
}

/// Budget envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionBudget {
    /// Schema version.
    pub schema_version: String,
    /// Cap.
    pub cap: BudgetCap,
    /// Accumulated consumption.
    pub consumed: Spend,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BudgetError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Cap field is zero.
    #[error("cap field {0:?} is zero")]
    CapZero(ExhaustionAxis),
    /// Consumed exceeds cap.
    #[error("consumed {0:?} exceeds cap")]
    ConsumedExceedsCap(ExhaustionAxis),
}

impl ExecutionBudget {
    /// New budget.
    pub fn new(cap: BudgetCap) -> Result<Self, BudgetError> {
        check_cap(&cap)?;
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            cap,
            consumed: Spend::ZERO,
        })
    }

    /// Attempt to admit a spend; if accepted, accumulator advances.
    pub fn admit(&mut self, spend: Spend) -> AdmitDecision {
        let projected = self.consumed.add(spend);
        if projected.wall_seconds > self.cap.max_wall_seconds {
            return AdmitDecision::Deny { axis: ExhaustionAxis::Time, projected, cap: self.cap };
        }
        if projected.tokens > self.cap.max_tokens {
            return AdmitDecision::Deny { axis: ExhaustionAxis::Tokens, projected, cap: self.cap };
        }
        if projected.dollars_micro > self.cap.max_dollars_micro {
            return AdmitDecision::Deny { axis: ExhaustionAxis::Cost, projected, cap: self.cap };
        }
        self.consumed = projected;
        AdmitDecision::Admit { total: projected }
    }

    /// Remaining headroom on each axis.
    pub fn remaining(&self) -> Spend {
        Spend {
            wall_seconds: self.cap.max_wall_seconds.saturating_sub(self.consumed.wall_seconds),
            tokens: self.cap.max_tokens.saturating_sub(self.consumed.tokens),
            dollars_micro: self.cap.max_dollars_micro.saturating_sub(self.consumed.dollars_micro),
        }
    }

    /// Reset accumulator.
    pub fn reset(&mut self) {
        self.consumed = Spend::ZERO;
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BudgetError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BudgetError::SchemaMismatch);
        }
        check_cap(&self.cap)?;
        if self.consumed.wall_seconds > self.cap.max_wall_seconds {
            return Err(BudgetError::ConsumedExceedsCap(ExhaustionAxis::Time));
        }
        if self.consumed.tokens > self.cap.max_tokens {
            return Err(BudgetError::ConsumedExceedsCap(ExhaustionAxis::Tokens));
        }
        if self.consumed.dollars_micro > self.cap.max_dollars_micro {
            return Err(BudgetError::ConsumedExceedsCap(ExhaustionAxis::Cost));
        }
        Ok(())
    }
}

fn check_cap(c: &BudgetCap) -> Result<(), BudgetError> {
    if c.max_wall_seconds == 0 { return Err(BudgetError::CapZero(ExhaustionAxis::Time)); }
    if c.max_tokens == 0 { return Err(BudgetError::CapZero(ExhaustionAxis::Tokens)); }
    if c.max_dollars_micro == 0 { return Err(BudgetError::CapZero(ExhaustionAxis::Cost)); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap() -> BudgetCap {
        BudgetCap { max_wall_seconds: 60, max_tokens: 10_000, max_dollars_micro: 1_000_000 }
    }

    #[test]
    fn zero_cap_rejected() {
        assert!(matches!(
            ExecutionBudget::new(BudgetCap { max_wall_seconds: 0, max_tokens: 1, max_dollars_micro: 1 }).unwrap_err(),
            BudgetError::CapZero(ExhaustionAxis::Time)
        ));
    }

    #[test]
    fn admit_within_cap() {
        let mut b = ExecutionBudget::new(cap()).unwrap();
        let d = b.admit(Spend { wall_seconds: 10, tokens: 100, dollars_micro: 1000 });
        assert!(matches!(d, AdmitDecision::Admit { .. }));
        assert_eq!(b.consumed.wall_seconds, 10);
    }

    #[test]
    fn deny_on_time() {
        let mut b = ExecutionBudget::new(cap()).unwrap();
        b.admit(Spend { wall_seconds: 50, tokens: 0, dollars_micro: 0 });
        let d = b.admit(Spend { wall_seconds: 20, tokens: 0, dollars_micro: 0 });
        assert!(matches!(d, AdmitDecision::Deny { axis: ExhaustionAxis::Time, .. }));
    }

    #[test]
    fn deny_on_tokens() {
        let mut b = ExecutionBudget::new(cap()).unwrap();
        let d = b.admit(Spend { wall_seconds: 0, tokens: 20_000, dollars_micro: 0 });
        assert!(matches!(d, AdmitDecision::Deny { axis: ExhaustionAxis::Tokens, .. }));
    }

    #[test]
    fn deny_on_cost() {
        let mut b = ExecutionBudget::new(cap()).unwrap();
        let d = b.admit(Spend { wall_seconds: 0, tokens: 0, dollars_micro: 2_000_000 });
        assert!(matches!(d, AdmitDecision::Deny { axis: ExhaustionAxis::Cost, .. }));
    }

    #[test]
    fn denied_spend_doesnt_advance() {
        let mut b = ExecutionBudget::new(cap()).unwrap();
        b.admit(Spend { wall_seconds: 0, tokens: 20_000, dollars_micro: 0 });
        assert_eq!(b.consumed, Spend::ZERO);
    }

    #[test]
    fn remaining_decreases_after_admit() {
        let mut b = ExecutionBudget::new(cap()).unwrap();
        b.admit(Spend { wall_seconds: 20, tokens: 200, dollars_micro: 200_000 });
        let r = b.remaining();
        assert_eq!(r.wall_seconds, 40);
        assert_eq!(r.tokens, 9_800);
        assert_eq!(r.dollars_micro, 800_000);
    }

    #[test]
    fn reset_clears_consumed() {
        let mut b = ExecutionBudget::new(cap()).unwrap();
        b.admit(Spend { wall_seconds: 30, tokens: 0, dollars_micro: 0 });
        b.reset();
        assert_eq!(b.consumed, Spend::ZERO);
    }

    #[test]
    fn validate_rejects_consumed_over_cap() {
        let mut b = ExecutionBudget::new(cap()).unwrap();
        b.consumed.wall_seconds = 999;
        assert!(matches!(b.validate().unwrap_err(), BudgetError::ConsumedExceedsCap(ExhaustionAxis::Time)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut b = ExecutionBudget::new(cap()).unwrap();
        b.schema_version = "9.9.9".into();
        assert!(matches!(b.validate().unwrap_err(), BudgetError::SchemaMismatch));
    }

    #[test]
    fn axis_serde_kebab() {
        assert_eq!(serde_json::to_string(&ExhaustionAxis::Time).unwrap(), "\"time\"");
        assert_eq!(serde_json::to_string(&ExhaustionAxis::Tokens).unwrap(), "\"tokens\"");
        assert_eq!(serde_json::to_string(&ExhaustionAxis::Cost).unwrap(), "\"cost\"");
    }

    #[test]
    fn budget_serde_roundtrip() {
        let mut b = ExecutionBudget::new(cap()).unwrap();
        b.admit(Spend { wall_seconds: 5, tokens: 50, dollars_micro: 500 });
        let j = serde_json::to_string(&b).unwrap();
        let back: ExecutionBudget = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
