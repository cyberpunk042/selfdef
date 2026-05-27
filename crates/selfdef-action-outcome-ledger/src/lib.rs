//! `selfdef-action-outcome-ledger` — action result accounting.
//!
//! Each `record(action_class, Outcome, ts_ms)` appends to a bounded
//! ring buffer of recent entries AND bumps per-class counters.
//! Class counters retain even after entries roll out of the ring.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Outcome.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    /// Succeeded.
    Success,
    /// Soft failure (recoverable).
    SoftFailure,
    /// Hard failure.
    HardFailure,
    /// Skipped.
    Skipped,
    /// Cancelled.
    Cancelled,
}

/// One recent record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// Action class label.
    pub action_class: String,
    /// Outcome.
    pub outcome: Outcome,
    /// ts.
    pub ts_ms: u64,
}

/// Per-class counters.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClassCounters {
    /// Success.
    pub success: u64,
    /// SoftFailure.
    pub soft_failure: u64,
    /// HardFailure.
    pub hard_failure: u64,
    /// Skipped.
    pub skipped: u64,
    /// Cancelled.
    pub cancelled: u64,
}

impl ClassCounters {
    /// Total.
    pub fn total(&self) -> u64 {
        self.success
            .saturating_add(self.soft_failure)
            .saturating_add(self.hard_failure)
            .saturating_add(self.skipped)
            .saturating_add(self.cancelled)
    }

    /// Success rate in basis points (1..=10000). Returns 0 if no records.
    pub fn success_rate_bp(&self) -> u32 {
        let t = self.total();
        if t == 0 {
            return 0;
        }
        ((self.success.saturating_mul(10_000)) / t) as u32
    }
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionOutcomeLedger {
    /// Schema version.
    pub schema_version: String,
    /// Ring capacity (recent entries).
    pub capacity: usize,
    /// Ring buffer.
    pub recent: VecDeque<Entry>,
    /// Per-class counters.
    pub counters: BTreeMap<String, ClassCounters>,
    /// Entries dropped (overflow).
    pub dropped: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum LedgerError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty class.
    #[error("action class empty")]
    EmptyClass,
    /// Zero capacity.
    #[error("capacity must be > 0")]
    ZeroCapacity,
}

impl ActionOutcomeLedger {
    /// New.
    pub fn new(capacity: usize) -> Result<Self, LedgerError> {
        if capacity == 0 {
            return Err(LedgerError::ZeroCapacity);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            capacity,
            recent: VecDeque::with_capacity(capacity),
            counters: BTreeMap::new(),
            dropped: 0,
        })
    }

    /// Record.
    pub fn record(
        &mut self,
        action_class: &str,
        outcome: Outcome,
        ts_ms: u64,
    ) -> Result<(), LedgerError> {
        if action_class.is_empty() {
            return Err(LedgerError::EmptyClass);
        }
        if self.recent.len() == self.capacity {
            self.recent.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }
        self.recent.push_back(Entry {
            action_class: action_class.into(),
            outcome,
            ts_ms,
        });
        let c = self.counters.entry(action_class.into()).or_default();
        match outcome {
            Outcome::Success => c.success = c.success.saturating_add(1),
            Outcome::SoftFailure => c.soft_failure = c.soft_failure.saturating_add(1),
            Outcome::HardFailure => c.hard_failure = c.hard_failure.saturating_add(1),
            Outcome::Skipped => c.skipped = c.skipped.saturating_add(1),
            Outcome::Cancelled => c.cancelled = c.cancelled.saturating_add(1),
        }
        Ok(())
    }

    /// Counters for a class.
    pub fn counters_of(&self, action_class: &str) -> Option<ClassCounters> {
        self.counters.get(action_class).copied()
    }

    /// Recent entries newest-first.
    pub fn recent_newest_first(&self) -> Vec<Entry> {
        self.recent.iter().rev().cloned().collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), LedgerError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(LedgerError::SchemaMismatch);
        }
        if self.capacity == 0 {
            return Err(LedgerError::ZeroCapacity);
        }
        for k in self.counters.keys() {
            if k.is_empty() {
                return Err(LedgerError::EmptyClass);
            }
        }
        for e in &self.recent {
            if e.action_class.is_empty() {
                return Err(LedgerError::EmptyClass);
            }
        }
        Ok(())
    }
}

impl Default for ActionOutcomeLedger {
    fn default() -> Self {
        Self::new(1000).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_count() {
        let mut l = ActionOutcomeLedger::new(10).unwrap();
        l.record("a", Outcome::Success, 0).unwrap();
        l.record("a", Outcome::HardFailure, 1).unwrap();
        let c = l.counters_of("a").unwrap();
        assert_eq!(c.success, 1);
        assert_eq!(c.hard_failure, 1);
        assert_eq!(c.total(), 2);
    }

    #[test]
    fn success_rate_bp() {
        let mut l = ActionOutcomeLedger::new(10).unwrap();
        // 7 successes, 3 failures → 7000 bp.
        for _ in 0..7 {
            l.record("a", Outcome::Success, 0).unwrap();
        }
        for _ in 0..3 {
            l.record("a", Outcome::HardFailure, 0).unwrap();
        }
        let c = l.counters_of("a").unwrap();
        assert_eq!(c.success_rate_bp(), 7000);
    }

    #[test]
    fn empty_success_rate_zero() {
        let c = ClassCounters::default();
        assert_eq!(c.success_rate_bp(), 0);
    }

    #[test]
    fn ring_drops_oldest_keeps_counters() {
        let mut l = ActionOutcomeLedger::new(2).unwrap();
        l.record("a", Outcome::Success, 0).unwrap();
        l.record("a", Outcome::Success, 1).unwrap();
        l.record("a", Outcome::HardFailure, 2).unwrap();
        // Ring keeps 2 most recent.
        assert_eq!(l.recent.len(), 2);
        assert_eq!(l.dropped, 1);
        // Counters preserved.
        assert_eq!(l.counters_of("a").unwrap().total(), 3);
    }

    #[test]
    fn recent_newest_first() {
        let mut l = ActionOutcomeLedger::new(10).unwrap();
        l.record("a", Outcome::Success, 0).unwrap();
        l.record("b", Outcome::Success, 1).unwrap();
        let r = l.recent_newest_first();
        assert_eq!(r[0].action_class, "b");
        assert_eq!(r[1].action_class, "a");
    }

    #[test]
    fn different_classes_isolated() {
        let mut l = ActionOutcomeLedger::new(10).unwrap();
        l.record("a", Outcome::Success, 0).unwrap();
        l.record("b", Outcome::HardFailure, 0).unwrap();
        assert_eq!(l.counters_of("a").unwrap().success, 1);
        assert_eq!(l.counters_of("b").unwrap().hard_failure, 1);
        assert_eq!(l.counters_of("a").unwrap().hard_failure, 0);
    }

    #[test]
    fn all_outcome_variants_count() {
        let mut l = ActionOutcomeLedger::new(10).unwrap();
        l.record("a", Outcome::Success, 0).unwrap();
        l.record("a", Outcome::SoftFailure, 0).unwrap();
        l.record("a", Outcome::HardFailure, 0).unwrap();
        l.record("a", Outcome::Skipped, 0).unwrap();
        l.record("a", Outcome::Cancelled, 0).unwrap();
        let c = l.counters_of("a").unwrap();
        assert_eq!(c.success, 1);
        assert_eq!(c.soft_failure, 1);
        assert_eq!(c.hard_failure, 1);
        assert_eq!(c.skipped, 1);
        assert_eq!(c.cancelled, 1);
    }

    #[test]
    fn zero_capacity_rejected() {
        assert!(matches!(
            ActionOutcomeLedger::new(0).unwrap_err(),
            LedgerError::ZeroCapacity
        ));
    }

    #[test]
    fn empty_class_rejected() {
        let mut l = ActionOutcomeLedger::new(10).unwrap();
        assert!(matches!(
            l.record("", Outcome::Success, 0).unwrap_err(),
            LedgerError::EmptyClass
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut l = ActionOutcomeLedger::new(10).unwrap();
        l.schema_version = "9.9.9".into();
        assert!(matches!(
            l.validate().unwrap_err(),
            LedgerError::SchemaMismatch
        ));
    }

    #[test]
    fn ledger_serde_roundtrip() {
        let mut l = ActionOutcomeLedger::new(10).unwrap();
        l.record("a", Outcome::Success, 0).unwrap();
        l.record("b", Outcome::HardFailure, 1).unwrap();
        let j = serde_json::to_string(&l).unwrap();
        let back: ActionOutcomeLedger = serde_json::from_str(&j).unwrap();
        assert_eq!(l, back);
    }
}
