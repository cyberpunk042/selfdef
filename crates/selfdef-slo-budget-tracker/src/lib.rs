//! `selfdef-slo-budget-tracker` — error-budget accounting.
//!
//! Each named SLO defines a target ratio (e.g. 0.999 = three nines).
//! The tracker records observations: `record_success(slo)` /
//! `record_failure(slo)`. `budget(slo)` returns:
//!   * `total` observations
//!   * `allowed_failures` (1 - target) × total
//!   * `actual_failures`
//!   * `burn_ratio` = actual / allowed (clamped at u64::MAX if
//!     `allowed == 0`)
//!
//! Ratios are encoded as basis points (×10000) — `target_bp = 9990`
//! means 99.9%.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One SLO.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Slo {
    /// Target ratio in basis points (10000 = 100%).
    pub target_bp: u32,
    /// Successes observed.
    pub successes: u64,
    /// Failures observed.
    pub failures: u64,
}

/// Budget snapshot.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Budget {
    /// Total events.
    pub total: u64,
    /// Failures permitted by SLO.
    pub allowed_failures: u64,
    /// Failures observed.
    pub actual_failures: u64,
    /// Remaining budget (allowed - actual, saturating).
    pub remaining: u64,
    /// burn_ratio_bp = actual / allowed × 10000.
    pub burn_ratio_bp: u32,
    /// Exhausted?
    pub exhausted: bool,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SloBudgetTracker {
    /// Schema version.
    pub schema_version: String,
    /// slo id → slo.
    pub slos: BTreeMap<String, Slo>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SloError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("slo id empty")]
    EmptyId,
    /// Target bp out of range.
    #[error("target_bp must be in 1..=10000, got {0}")]
    BadTarget(u32),
    /// Unknown slo.
    #[error("unknown slo: {0}")]
    UnknownSlo(String),
}

impl SloBudgetTracker {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            slos: BTreeMap::new(),
        }
    }

    /// Register an SLO.
    pub fn register(&mut self, id: &str, target_bp: u32) -> Result<(), SloError> {
        if id.is_empty() {
            return Err(SloError::EmptyId);
        }
        if target_bp == 0 || target_bp > 10000 {
            return Err(SloError::BadTarget(target_bp));
        }
        self.slos.insert(
            id.into(),
            Slo {
                target_bp,
                successes: 0,
                failures: 0,
            },
        );
        Ok(())
    }

    /// Record success.
    pub fn record_success(&mut self, id: &str) -> Result<(), SloError> {
        let s = self
            .slos
            .get_mut(id)
            .ok_or_else(|| SloError::UnknownSlo(id.into()))?;
        s.successes = s.successes.saturating_add(1);
        Ok(())
    }

    /// Record failure.
    pub fn record_failure(&mut self, id: &str) -> Result<(), SloError> {
        let s = self
            .slos
            .get_mut(id)
            .ok_or_else(|| SloError::UnknownSlo(id.into()))?;
        s.failures = s.failures.saturating_add(1);
        Ok(())
    }

    /// Budget snapshot.
    pub fn budget(&self, id: &str) -> Option<Budget> {
        let s = self.slos.get(id)?;
        let total = s.successes.saturating_add(s.failures);
        // allowed = total × (10000 - target_bp) / 10000
        // (integer math — floor toward 0)
        let error_bp = (10000 - s.target_bp) as u64;
        let allowed = (total.saturating_mul(error_bp)) / 10000;
        let actual = s.failures;
        let remaining = allowed.saturating_sub(actual);
        let burn_ratio_bp = if allowed == 0 {
            if actual == 0 { 0 } else { u32::MAX }
        } else {
            // ratio × 10000, clamped
            let r = (actual.saturating_mul(10000)) / allowed;
            r.min(u32::MAX as u64) as u32
        };
        let exhausted = actual >= allowed && actual > 0;
        Some(Budget {
            total,
            allowed_failures: allowed,
            actual_failures: actual,
            remaining,
            burn_ratio_bp,
            exhausted,
        })
    }

    /// Reset counters for an SLO.
    pub fn reset(&mut self, id: &str) -> Result<(), SloError> {
        let s = self
            .slos
            .get_mut(id)
            .ok_or_else(|| SloError::UnknownSlo(id.into()))?;
        s.successes = 0;
        s.failures = 0;
        Ok(())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), SloError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SloError::SchemaMismatch);
        }
        for (id, s) in &self.slos {
            if id.is_empty() {
                return Err(SloError::EmptyId);
            }
            if s.target_bp == 0 || s.target_bp > 10000 {
                return Err(SloError::BadTarget(s.target_bp));
            }
        }
        Ok(())
    }
}

impl Default for SloBudgetTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_nines_target() {
        let mut t = SloBudgetTracker::new();
        t.register("api", 9990).unwrap();
        // 1000 events, 1 failure — exactly the SLO.
        for _ in 0..999 {
            t.record_success("api").unwrap();
        }
        t.record_failure("api").unwrap();
        let b = t.budget("api").unwrap();
        assert_eq!(b.total, 1000);
        assert_eq!(b.allowed_failures, 1);
        assert_eq!(b.actual_failures, 1);
        assert_eq!(b.remaining, 0);
        assert!(b.exhausted);
    }

    #[test]
    fn within_budget() {
        let mut t = SloBudgetTracker::new();
        t.register("api", 9900).unwrap();
        // 100 events, 0 failures.
        for _ in 0..100 {
            t.record_success("api").unwrap();
        }
        let b = t.budget("api").unwrap();
        assert!(!b.exhausted);
        assert_eq!(b.actual_failures, 0);
    }

    #[test]
    fn over_budget() {
        let mut t = SloBudgetTracker::new();
        t.register("api", 9000).unwrap(); // 90% target → 10% error budget
        for _ in 0..10 {
            t.record_success("api").unwrap();
        }
        for _ in 0..5 {
            t.record_failure("api").unwrap();
        }
        let b = t.budget("api").unwrap();
        // total 15, allowed = 15 × 1000 / 10000 = 1
        assert_eq!(b.allowed_failures, 1);
        assert_eq!(b.actual_failures, 5);
        assert!(b.exhausted);
        assert!(b.burn_ratio_bp >= 10000);
    }

    #[test]
    fn empty_slo_budget_zero_burn() {
        let mut t = SloBudgetTracker::new();
        t.register("api", 9990).unwrap();
        let b = t.budget("api").unwrap();
        assert_eq!(b.total, 0);
        assert_eq!(b.burn_ratio_bp, 0);
    }

    #[test]
    fn reset_clears_counters() {
        let mut t = SloBudgetTracker::new();
        t.register("api", 9990).unwrap();
        t.record_failure("api").unwrap();
        t.reset("api").unwrap();
        let b = t.budget("api").unwrap();
        assert_eq!(b.total, 0);
    }

    #[test]
    fn bad_target_rejected() {
        let mut t = SloBudgetTracker::new();
        assert!(matches!(
            t.register("a", 0).unwrap_err(),
            SloError::BadTarget(0)
        ));
        assert!(matches!(
            t.register("a", 10001).unwrap_err(),
            SloError::BadTarget(10001)
        ));
    }

    #[test]
    fn unknown_slo_rejected() {
        let mut t = SloBudgetTracker::new();
        assert!(matches!(
            t.record_success("nope").unwrap_err(),
            SloError::UnknownSlo(_)
        ));
    }

    #[test]
    fn empty_id_rejected() {
        let mut t = SloBudgetTracker::new();
        assert!(matches!(
            t.register("", 9990).unwrap_err(),
            SloError::EmptyId
        ));
    }

    #[test]
    fn unknown_budget_returns_none() {
        let t = SloBudgetTracker::new();
        assert!(t.budget("nope").is_none());
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = SloBudgetTracker::new();
        t.schema_version = "9.9.9".into();
        assert!(matches!(
            t.validate().unwrap_err(),
            SloError::SchemaMismatch
        ));
    }

    #[test]
    fn slo_serde_roundtrip() {
        let mut t = SloBudgetTracker::new();
        t.register("api", 9900).unwrap();
        t.record_success("api").unwrap();
        let j = serde_json::to_string(&t).unwrap();
        let back: SloBudgetTracker = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
