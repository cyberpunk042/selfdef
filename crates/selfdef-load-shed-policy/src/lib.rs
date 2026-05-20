//! `selfdef-load-shed-policy` — priority-based load shedding.
//!
//! The policy holds a current `load_ratio_bp` (0..=10000; basis
//! points of saturation). Each request carries a `priority`
//! Critical/High/Normal/Low/Bulk. Buckets drop progressively:
//!   * 10000 → drop Bulk + Low + Normal + High + Critical (panic)
//!   * 9000  → drop Bulk + Low + Normal + High
//!   * 8000  → drop Bulk + Low + Normal
//!   * 6500  → drop Bulk + Low
//!   * 5000  → drop Bulk
//!   * below → admit all
//!
//! Thresholds are operator-configurable. `decide(priority)` returns
//! Admit/Shed. `record(verdict)` tallies counts per priority.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Priority levels.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Priority {
    /// Bulk (lowest).
    Bulk,
    /// Low.
    Low,
    /// Normal.
    Normal,
    /// High.
    High,
    /// Critical (highest).
    Critical,
}

/// Per-priority thresholds (load_ratio_bp at which this priority starts being shed).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Thresholds {
    /// Bulk shed threshold.
    pub bulk_bp: u32,
    /// Low shed threshold.
    pub low_bp: u32,
    /// Normal shed threshold.
    pub normal_bp: u32,
    /// High shed threshold.
    pub high_bp: u32,
    /// Critical shed threshold (10000 = essentially never).
    pub critical_bp: u32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            bulk_bp: 5000,
            low_bp: 6500,
            normal_bp: 8000,
            high_bp: 9000,
            critical_bp: 10000,
        }
    }
}

/// Per-priority counters.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counters {
    /// Admitted total.
    pub admitted: u64,
    /// Shed total.
    pub shed: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoadShedPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Current load.
    pub load_ratio_bp: u32,
    /// Thresholds.
    pub thresholds: Thresholds,
    /// Per-priority counters.
    pub counters: BTreeMap<String, Counters>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ShedVerdict {
    /// Admit.
    Admit,
    /// Shed.
    Shed,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ShedError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Bp range.
    #[error("bp must be in 0..=10000, got {0}")]
    BadBp(u32),
}

impl LoadShedPolicy {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            load_ratio_bp: 0,
            thresholds: Thresholds::default(),
            counters: BTreeMap::new(),
        }
    }

    /// Set current load.
    pub fn set_load(&mut self, load_ratio_bp: u32) -> Result<(), ShedError> {
        if load_ratio_bp > 10000 { return Err(ShedError::BadBp(load_ratio_bp)); }
        self.load_ratio_bp = load_ratio_bp;
        Ok(())
    }

    /// Replace thresholds.
    pub fn set_thresholds(&mut self, t: Thresholds) -> Result<(), ShedError> {
        for v in [t.bulk_bp, t.low_bp, t.normal_bp, t.high_bp, t.critical_bp] {
            if v > 10000 { return Err(ShedError::BadBp(v)); }
        }
        self.thresholds = t;
        Ok(())
    }

    /// Decide (pure, no telemetry).
    pub fn decide(&self, priority: Priority) -> ShedVerdict {
        let threshold = match priority {
            Priority::Bulk => self.thresholds.bulk_bp,
            Priority::Low => self.thresholds.low_bp,
            Priority::Normal => self.thresholds.normal_bp,
            Priority::High => self.thresholds.high_bp,
            Priority::Critical => self.thresholds.critical_bp,
        };
        if self.load_ratio_bp >= threshold { ShedVerdict::Shed } else { ShedVerdict::Admit }
    }

    /// Observe (records counters).
    pub fn observe(&mut self, priority: Priority) -> ShedVerdict {
        let v = self.decide(priority);
        let key = match priority {
            Priority::Bulk => "bulk",
            Priority::Low => "low",
            Priority::Normal => "normal",
            Priority::High => "high",
            Priority::Critical => "critical",
        };
        let c = self.counters.entry(key.into()).or_default();
        match v {
            ShedVerdict::Admit => c.admitted = c.admitted.saturating_add(1),
            ShedVerdict::Shed => c.shed = c.shed.saturating_add(1),
        }
        v
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ShedError> {
        if self.schema_version != SCHEMA_VERSION { return Err(ShedError::SchemaMismatch); }
        if self.load_ratio_bp > 10000 { return Err(ShedError::BadBp(self.load_ratio_bp)); }
        for v in [
            self.thresholds.bulk_bp,
            self.thresholds.low_bp,
            self.thresholds.normal_bp,
            self.thresholds.high_bp,
            self.thresholds.critical_bp,
        ] {
            if v > 10000 { return Err(ShedError::BadBp(v)); }
        }
        Ok(())
    }
}

impl Default for LoadShedPolicy {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_load_admits_all() {
        let mut p = LoadShedPolicy::new();
        p.set_load(0).unwrap();
        for &pr in &[Priority::Bulk, Priority::Low, Priority::Normal, Priority::High, Priority::Critical] {
            assert_eq!(p.decide(pr), ShedVerdict::Admit);
        }
    }

    #[test]
    fn moderate_load_sheds_bulk() {
        let mut p = LoadShedPolicy::new();
        p.set_load(5500).unwrap(); // > bulk threshold 5000
        assert_eq!(p.decide(Priority::Bulk), ShedVerdict::Shed);
        assert_eq!(p.decide(Priority::Low), ShedVerdict::Admit);
        assert_eq!(p.decide(Priority::Critical), ShedVerdict::Admit);
    }

    #[test]
    fn high_load_sheds_through_normal() {
        let mut p = LoadShedPolicy::new();
        p.set_load(8500).unwrap();
        assert_eq!(p.decide(Priority::Bulk), ShedVerdict::Shed);
        assert_eq!(p.decide(Priority::Low), ShedVerdict::Shed);
        assert_eq!(p.decide(Priority::Normal), ShedVerdict::Shed);
        assert_eq!(p.decide(Priority::High), ShedVerdict::Admit);
        assert_eq!(p.decide(Priority::Critical), ShedVerdict::Admit);
    }

    #[test]
    fn panic_load_sheds_high() {
        let mut p = LoadShedPolicy::new();
        p.set_load(9500).unwrap();
        assert_eq!(p.decide(Priority::High), ShedVerdict::Shed);
        assert_eq!(p.decide(Priority::Critical), ShedVerdict::Admit);
    }

    #[test]
    fn max_load_critical_still_admitted_by_default() {
        let mut p = LoadShedPolicy::new();
        // Default critical_bp = 10000 → load 9999 stays under.
        p.set_load(9999).unwrap();
        assert_eq!(p.decide(Priority::Critical), ShedVerdict::Admit);
    }

    #[test]
    fn observe_counts() {
        let mut p = LoadShedPolicy::new();
        p.set_load(5500).unwrap();
        p.observe(Priority::Bulk); // shed
        p.observe(Priority::Critical); // admit
        assert_eq!(p.counters["bulk"].shed, 1);
        assert_eq!(p.counters["critical"].admitted, 1);
    }

    #[test]
    fn custom_thresholds() {
        let mut p = LoadShedPolicy::new();
        p.set_thresholds(Thresholds { bulk_bp: 1000, low_bp: 2000, normal_bp: 3000, high_bp: 4000, critical_bp: 5000 }).unwrap();
        p.set_load(1500).unwrap();
        assert_eq!(p.decide(Priority::Bulk), ShedVerdict::Shed);
        assert_eq!(p.decide(Priority::Low), ShedVerdict::Admit);
    }

    #[test]
    fn bad_bp_rejected() {
        let mut p = LoadShedPolicy::new();
        assert!(matches!(p.set_load(10001).unwrap_err(), ShedError::BadBp(_)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = LoadShedPolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), ShedError::SchemaMismatch));
    }

    #[test]
    fn shed_serde_roundtrip() {
        let mut p = LoadShedPolicy::new();
        p.set_load(5500).unwrap();
        p.observe(Priority::Bulk);
        let j = serde_json::to_string(&p).unwrap();
        let back: LoadShedPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
