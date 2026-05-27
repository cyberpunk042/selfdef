//! `selfdef-quota-table` — per-key quotas with periodic reset.
//!
//! register(key, limit, period_ms) installs a quota.
//! consume(key, amount, now) advances the period if elapsed
//! then admits the request iff used+amount <= limit.
//! remaining(key, now) accounts for elapsed period.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Quota.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Quota {
    /// Limit per period.
    pub limit: u64,
    /// Period ms.
    pub period_ms: u64,
    /// Used in current period.
    pub used: u64,
    /// Last reset ts ms.
    pub last_reset_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuotaTable {
    /// Schema version.
    pub schema_version: String,
    /// key → quota.
    pub quotas: BTreeMap<String, Quota>,
    /// Total denials.
    pub denials: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum QuotaError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("key empty")]
    EmptyKey,
    /// Zero amount.
    #[error("amount must be >= 1")]
    ZeroAmount,
    /// Zero limit.
    #[error("limit must be >= 1")]
    ZeroLimit,
    /// Zero period.
    #[error("period_ms must be >= 1")]
    ZeroPeriod,
    /// Unknown key.
    #[error("unknown quota key: {0}")]
    UnknownKey(String),
    /// Exceeded.
    #[error("quota exceeded: need {need}, available {available}")]
    Exceeded {
        /// Needed.
        need: u64,
        /// Available.
        available: u64,
    },
}

impl QuotaTable {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            quotas: BTreeMap::new(),
            denials: 0,
        }
    }

    /// Register.
    pub fn register(
        &mut self,
        key: &str,
        limit: u64,
        period_ms: u64,
        now_ms: u64,
    ) -> Result<(), QuotaError> {
        if key.is_empty() {
            return Err(QuotaError::EmptyKey);
        }
        if limit == 0 {
            return Err(QuotaError::ZeroLimit);
        }
        if period_ms == 0 {
            return Err(QuotaError::ZeroPeriod);
        }
        self.quotas.insert(
            key.into(),
            Quota {
                limit,
                period_ms,
                used: 0,
                last_reset_ms: now_ms,
            },
        );
        Ok(())
    }

    fn advance(&mut self, key: &str, now_ms: u64) {
        if let Some(q) = self.quotas.get_mut(key) {
            if now_ms.saturating_sub(q.last_reset_ms) >= q.period_ms {
                q.used = 0;
                q.last_reset_ms = now_ms;
            }
        }
    }

    /// Consume.
    pub fn consume(&mut self, key: &str, amount: u64, now_ms: u64) -> Result<(), QuotaError> {
        if amount == 0 {
            return Err(QuotaError::ZeroAmount);
        }
        if !self.quotas.contains_key(key) {
            return Err(QuotaError::UnknownKey(key.into()));
        }
        self.advance(key, now_ms);
        let q = self.quotas.get_mut(key).unwrap();
        let available = q.limit.saturating_sub(q.used);
        if amount > available {
            self.denials = self.denials.saturating_add(1);
            return Err(QuotaError::Exceeded {
                need: amount,
                available,
            });
        }
        q.used = q.used.saturating_add(amount);
        Ok(())
    }

    /// Remaining (after period advance).
    pub fn remaining(&mut self, key: &str, now_ms: u64) -> Option<u64> {
        if !self.quotas.contains_key(key) {
            return None;
        }
        self.advance(key, now_ms);
        self.quotas.get(key).map(|q| q.limit.saturating_sub(q.used))
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), QuotaError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(QuotaError::SchemaMismatch);
        }
        for (k, q) in &self.quotas {
            if k.is_empty() {
                return Err(QuotaError::EmptyKey);
            }
            if q.limit == 0 {
                return Err(QuotaError::ZeroLimit);
            }
            if q.period_ms == 0 {
                return Err(QuotaError::ZeroPeriod);
            }
        }
        Ok(())
    }
}

impl Default for QuotaTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consume_within_limit() {
        let mut t = QuotaTable::new();
        t.register("api", 10, 1000, 0).unwrap();
        t.consume("api", 5, 100).unwrap();
        assert_eq!(t.remaining("api", 100), Some(5));
    }

    #[test]
    fn exceeded_rejected() {
        let mut t = QuotaTable::new();
        t.register("api", 10, 1000, 0).unwrap();
        t.consume("api", 8, 100).unwrap();
        assert!(matches!(
            t.consume("api", 5, 200).unwrap_err(),
            QuotaError::Exceeded { .. }
        ));
        assert_eq!(t.denials, 1);
    }

    #[test]
    fn period_resets() {
        let mut t = QuotaTable::new();
        t.register("api", 5, 1000, 0).unwrap();
        t.consume("api", 5, 100).unwrap();
        // Past period.
        t.consume("api", 3, 1500).unwrap();
        assert_eq!(t.remaining("api", 1500), Some(2));
    }

    #[test]
    fn unknown_key_rejected() {
        let mut t = QuotaTable::new();
        assert!(matches!(
            t.consume("nope", 1, 0).unwrap_err(),
            QuotaError::UnknownKey(_)
        ));
    }

    #[test]
    fn bad_inputs_rejected() {
        let mut t = QuotaTable::new();
        assert!(matches!(
            t.register("", 1, 1, 0).unwrap_err(),
            QuotaError::EmptyKey
        ));
        assert!(matches!(
            t.register("a", 0, 1, 0).unwrap_err(),
            QuotaError::ZeroLimit
        ));
        assert!(matches!(
            t.register("a", 1, 0, 0).unwrap_err(),
            QuotaError::ZeroPeriod
        ));
        t.register("a", 1, 1, 0).unwrap();
        assert!(matches!(
            t.consume("a", 0, 0).unwrap_err(),
            QuotaError::ZeroAmount
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = QuotaTable::new();
        t.schema_version = "9.9.9".into();
        assert!(matches!(
            t.validate().unwrap_err(),
            QuotaError::SchemaMismatch
        ));
    }

    #[test]
    fn table_serde_roundtrip() {
        let mut t = QuotaTable::new();
        t.register("api", 10, 1000, 0).unwrap();
        let j = serde_json::to_string(&t).unwrap();
        let back: QuotaTable = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
