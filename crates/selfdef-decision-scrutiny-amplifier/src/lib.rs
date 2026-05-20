//! `selfdef-decision-scrutiny-amplifier` — failure-driven scrutiny tier.
//!
//! Each actor's failures within `window_ms` are counted. `level(actor,
//! now_ms)` returns the lowest matching `Tier`:
//!
//!   * `Normal`    — failures < elevated_at
//!   * `Elevated`  — elevated_at ≤ failures < high_at
//!   * `High`      — high_at ≤ failures < critical_at
//!   * `Critical`  — failures ≥ critical_at
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tier {
    /// Normal.
    Normal,
    /// Elevated.
    Elevated,
    /// High.
    High,
    /// Critical.
    Critical,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionScrutinyAmplifier {
    /// Schema version.
    pub schema_version: String,
    /// Window width (ms).
    pub window_ms: u64,
    /// Tier thresholds (failures count).
    pub elevated_at: u32,
    /// Tier thresholds.
    pub high_at: u32,
    /// Tier thresholds.
    pub critical_at: u32,
    /// actor → Vec<failure ts>.
    pub failures: BTreeMap<String, Vec<u64>>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum AmpError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty actor.
    #[error("actor empty")]
    EmptyActor,
    /// Tier thresholds not strictly increasing.
    #[error("thresholds not strictly increasing: {0} {1} {2}")]
    BadThresholds(u32, u32, u32),
    /// Non-monotonic ts.
    #[error("non-monotonic ts: prev {prev} > new {new}")]
    NonMonotonic {
        /// prev.
        prev: u64,
        /// new.
        new: u64,
    },
}

impl DecisionScrutinyAmplifier {
    /// New.
    pub fn new(window_ms: u64, elevated_at: u32, high_at: u32, critical_at: u32) -> Result<Self, AmpError> {
        if !(elevated_at < high_at && high_at < critical_at) {
            return Err(AmpError::BadThresholds(elevated_at, high_at, critical_at));
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            window_ms,
            elevated_at,
            high_at,
            critical_at,
            failures: BTreeMap::new(),
        })
    }

    /// Record a decision.
    pub fn record_decision(&mut self, actor: &str, ok: bool, ts_ms: u64) -> Result<(), AmpError> {
        if actor.is_empty() { return Err(AmpError::EmptyActor); }
        if ok { return Ok(()); }
        let v = self.failures.entry(actor.into()).or_default();
        if let Some(&last) = v.last() {
            if ts_ms < last {
                return Err(AmpError::NonMonotonic { prev: last, new: ts_ms });
            }
        }
        v.push(ts_ms);
        Ok(())
    }

    /// Tier.
    pub fn level(&self, actor: &str, now_ms: u64) -> Tier {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        let count = self.failures.get(actor)
            .map(|v| v.iter().filter(|t| **t >= cutoff && **t <= now_ms).count() as u32)
            .unwrap_or(0);
        if count >= self.critical_at { Tier::Critical }
        else if count >= self.high_at { Tier::High }
        else if count >= self.elevated_at { Tier::Elevated }
        else { Tier::Normal }
    }

    /// Drop out-of-window failures.
    pub fn rotate(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        for v in self.failures.values_mut() {
            v.retain(|t| *t >= cutoff);
        }
        self.failures.retain(|_, v| !v.is_empty());
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), AmpError> {
        if self.schema_version != SCHEMA_VERSION { return Err(AmpError::SchemaMismatch); }
        if !(self.elevated_at < self.high_at && self.high_at < self.critical_at) {
            return Err(AmpError::BadThresholds(self.elevated_at, self.high_at, self.critical_at));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn amp() -> DecisionScrutinyAmplifier {
        DecisionScrutinyAmplifier::new(60_000, 1, 3, 5).unwrap()
    }

    #[test]
    fn thresholds_must_increase() {
        assert!(matches!(
            DecisionScrutinyAmplifier::new(1000, 3, 2, 1).unwrap_err(),
            AmpError::BadThresholds(_, _, _)
        ));
    }

    #[test]
    fn no_failures_normal() {
        let a = amp();
        assert_eq!(a.level("actor", 1000), Tier::Normal);
    }

    #[test]
    fn one_failure_elevated() {
        let mut a = amp();
        a.record_decision("actor", false, 0).unwrap();
        assert_eq!(a.level("actor", 1000), Tier::Elevated);
    }

    #[test]
    fn ok_decisions_dont_count() {
        let mut a = amp();
        for i in 0..10 {
            a.record_decision("actor", true, i * 100).unwrap();
        }
        assert_eq!(a.level("actor", 5000), Tier::Normal);
    }

    #[test]
    fn three_failures_high() {
        let mut a = amp();
        for i in 0..3 { a.record_decision("actor", false, i * 100).unwrap(); }
        assert_eq!(a.level("actor", 5000), Tier::High);
    }

    #[test]
    fn five_failures_critical() {
        let mut a = amp();
        for i in 0..5 { a.record_decision("actor", false, i * 100).unwrap(); }
        assert_eq!(a.level("actor", 5000), Tier::Critical);
    }

    #[test]
    fn failures_age_out() {
        let mut a = amp();
        for i in 0..5 { a.record_decision("actor", false, i * 100).unwrap(); }
        // Far past window.
        assert_eq!(a.level("actor", 5_000_000), Tier::Normal);
    }

    #[test]
    fn nonmonotonic_rejected() {
        let mut a = amp();
        a.record_decision("actor", false, 200).unwrap();
        assert!(matches!(a.record_decision("actor", false, 100).unwrap_err(), AmpError::NonMonotonic { .. }));
    }

    #[test]
    fn rotate_drops_old() {
        let mut a = amp();
        a.record_decision("actor", false, 0).unwrap();
        a.rotate(5_000_000);
        assert!(a.failures.is_empty());
    }

    #[test]
    fn schema_drift_rejected() {
        let mut a = amp();
        a.schema_version = "9.9.9".into();
        assert!(matches!(a.validate().unwrap_err(), AmpError::SchemaMismatch));
    }

    #[test]
    fn amp_serde_roundtrip() {
        let mut a = amp();
        a.record_decision("actor", false, 0).unwrap();
        let j = serde_json::to_string(&a).unwrap();
        let back: DecisionScrutinyAmplifier = serde_json::from_str(&j).unwrap();
        assert_eq!(a, back);
    }
}
