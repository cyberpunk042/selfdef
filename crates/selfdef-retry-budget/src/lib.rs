//! `selfdef-retry-budget` — per-key bounded retry budget.
//!
//! try_consume(key, now) succeeds and bumps used iff used <
//! budget within the current window. Windows reset on
//! (now - window_start_ms) >= window_ms. exhausted returns
//! keys whose used >= budget within current window.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-key state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyState {
    /// Used within current window.
    pub used: u32,
    /// Window start ms.
    pub window_start_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetryBudget {
    /// Schema version.
    pub schema_version: String,
    /// Budget per window.
    pub budget: u32,
    /// Window ms.
    pub window_ms: u64,
    /// key → state.
    pub keys: BTreeMap<String, KeyState>,
    /// Total denials.
    pub denials: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BudgetError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("key empty")]
    EmptyKey,
    /// Zero budget.
    #[error("budget must be >= 1")]
    ZeroBudget,
    /// Zero window.
    #[error("window_ms must be >= 1")]
    ZeroWindow,
    /// Exhausted.
    #[error("budget exhausted")]
    Exhausted,
}

impl RetryBudget {
    /// New.
    pub fn new(budget: u32, window_ms: u64) -> Result<Self, BudgetError> {
        if budget == 0 { return Err(BudgetError::ZeroBudget); }
        if window_ms == 0 { return Err(BudgetError::ZeroWindow); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            budget,
            window_ms,
            keys: BTreeMap::new(),
            denials: 0,
        })
    }

    /// Try to consume one retry for key.
    pub fn try_consume(&mut self, key: &str, now_ms: u64) -> Result<(), BudgetError> {
        if key.is_empty() { return Err(BudgetError::EmptyKey); }
        let entry = self.keys.entry(key.into()).or_insert(KeyState { used: 0, window_start_ms: now_ms });
        if now_ms.saturating_sub(entry.window_start_ms) >= self.window_ms {
            entry.used = 0;
            entry.window_start_ms = now_ms;
        }
        if entry.used >= self.budget {
            self.denials = self.denials.saturating_add(1);
            return Err(BudgetError::Exhausted);
        }
        entry.used = entry.used.saturating_add(1);
        Ok(())
    }

    /// Used count for key in current window (re-checks expiry).
    pub fn used(&self, key: &str, now_ms: u64) -> u32 {
        match self.keys.get(key) {
            Some(s) if now_ms.saturating_sub(s.window_start_ms) < self.window_ms => s.used,
            _ => 0,
        }
    }

    /// Keys currently exhausted.
    pub fn exhausted(&self, now_ms: u64) -> Vec<&str> {
        self.keys.iter()
            .filter(|(_, s)| now_ms.saturating_sub(s.window_start_ms) < self.window_ms && s.used >= self.budget)
            .map(|(k, _)| k.as_str())
            .collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BudgetError> {
        if self.schema_version != SCHEMA_VERSION { return Err(BudgetError::SchemaMismatch); }
        if self.budget == 0 { return Err(BudgetError::ZeroBudget); }
        if self.window_ms == 0 { return Err(BudgetError::ZeroWindow); }
        for k in self.keys.keys() {
            if k.is_empty() { return Err(BudgetError::EmptyKey); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consumes_up_to_budget() {
        let mut b = RetryBudget::new(3, 1000).unwrap();
        b.try_consume("a", 0).unwrap();
        b.try_consume("a", 100).unwrap();
        b.try_consume("a", 200).unwrap();
        assert!(matches!(b.try_consume("a", 300).unwrap_err(), BudgetError::Exhausted));
        assert_eq!(b.denials, 1);
    }

    #[test]
    fn window_resets() {
        let mut b = RetryBudget::new(2, 1000).unwrap();
        b.try_consume("a", 0).unwrap();
        b.try_consume("a", 100).unwrap();
        assert!(b.try_consume("a", 200).is_err());
        // After window.
        b.try_consume("a", 1200).unwrap();
        assert_eq!(b.used("a", 1200), 1);
    }

    #[test]
    fn per_key_independent() {
        let mut b = RetryBudget::new(2, 1000).unwrap();
        b.try_consume("a", 0).unwrap();
        b.try_consume("a", 0).unwrap();
        // "b" still has full budget.
        b.try_consume("b", 0).unwrap();
        b.try_consume("b", 0).unwrap();
        assert_eq!(b.used("a", 100), 2);
        assert_eq!(b.used("b", 100), 2);
    }

    #[test]
    fn exhausted_lists_keys() {
        let mut b = RetryBudget::new(1, 1000).unwrap();
        b.try_consume("a", 0).unwrap();
        b.try_consume("b", 0).unwrap();
        let ex = b.exhausted(100);
        assert_eq!(ex.len(), 2);
    }

    #[test]
    fn bad_inputs_rejected() {
        let mut b = RetryBudget::new(2, 1000).unwrap();
        assert!(matches!(b.try_consume("", 0).unwrap_err(), BudgetError::EmptyKey));
        assert!(matches!(RetryBudget::new(0, 1000).unwrap_err(), BudgetError::ZeroBudget));
        assert!(matches!(RetryBudget::new(2, 0).unwrap_err(), BudgetError::ZeroWindow));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut b = RetryBudget::new(2, 1000).unwrap();
        b.schema_version = "9.9.9".into();
        assert!(matches!(b.validate().unwrap_err(), BudgetError::SchemaMismatch));
    }

    #[test]
    fn budget_serde_roundtrip() {
        let mut b = RetryBudget::new(2, 1000).unwrap();
        b.try_consume("a", 0).unwrap();
        let j = serde_json::to_string(&b).unwrap();
        let back: RetryBudget = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
