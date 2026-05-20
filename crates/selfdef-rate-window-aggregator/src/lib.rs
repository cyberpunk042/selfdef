//! `selfdef-rate-window-aggregator` — per-key events-per-window count.
//!
//! `record(key, ts)` appends an event timestamp; `count(key, now)`
//! returns how many events for that key fall within `[now-window_ms,
//! now]`. `rotate(now)` evicts all per-key timestamps older than the
//! window globally.
//!
//! Pure ledger — no policy. Pair with `selfdef-rate-limit-policy`
//! when you need a decision gate.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateWindowAggregator {
    /// Schema version.
    pub schema_version: String,
    /// Window width (ms).
    pub window_ms: u64,
    /// key → sorted Vec<ts_ms>.
    pub series: BTreeMap<String, Vec<u64>>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum AggError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty key.
    #[error("key empty")]
    EmptyKey,
    /// Non-monotonic.
    #[error("non-monotonic ts: prev {prev} > new {new}")]
    NonMonotonic {
        /// prev.
        prev: u64,
        /// new.
        new: u64,
    },
}

impl RateWindowAggregator {
    /// New.
    pub fn new(window_ms: u64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            window_ms,
            series: BTreeMap::new(),
        }
    }

    /// Record an event.
    pub fn record(&mut self, key: &str, ts_ms: u64) -> Result<(), AggError> {
        if key.is_empty() { return Err(AggError::EmptyKey); }
        let v = self.series.entry(key.into()).or_default();
        if let Some(&last) = v.last() {
            if ts_ms < last {
                return Err(AggError::NonMonotonic { prev: last, new: ts_ms });
            }
        }
        v.push(ts_ms);
        Ok(())
    }

    /// Count events for `key` in `[now-window_ms, now]`.
    pub fn count(&self, key: &str, now_ms: u64) -> usize {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        match self.series.get(key) {
            Some(v) => v.iter().filter(|t| **t >= cutoff && **t <= now_ms).count(),
            None => 0,
        }
    }

    /// Drop ts older than window globally.
    pub fn rotate(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        for v in self.series.values_mut() {
            v.retain(|t| *t >= cutoff);
        }
        self.series.retain(|_, v| !v.is_empty());
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), AggError> {
        if self.schema_version != SCHEMA_VERSION { return Err(AggError::SchemaMismatch); }
        for (k, v) in &self.series {
            if k.is_empty() { return Err(AggError::EmptyKey); }
            let mut prev = 0u64;
            for &t in v {
                if t < prev { return Err(AggError::NonMonotonic { prev, new: t }); }
                prev = t;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_count() {
        let mut a = RateWindowAggregator::new(1000);
        a.record("k", 100).unwrap();
        a.record("k", 200).unwrap();
        assert_eq!(a.count("k", 500), 2);
    }

    #[test]
    fn count_excludes_outside_window() {
        let mut a = RateWindowAggregator::new(1000);
        a.record("k", 100).unwrap();
        a.record("k", 200).unwrap();
        assert_eq!(a.count("k", 2000), 0);
    }

    #[test]
    fn keys_independent() {
        let mut a = RateWindowAggregator::new(1000);
        a.record("k1", 100).unwrap();
        a.record("k2", 100).unwrap();
        assert_eq!(a.count("k1", 200), 1);
        assert_eq!(a.count("k2", 200), 1);
        assert_eq!(a.count("k3", 200), 0);
    }

    #[test]
    fn nonmonotonic_rejected() {
        let mut a = RateWindowAggregator::new(1000);
        a.record("k", 200).unwrap();
        assert!(matches!(a.record("k", 100).unwrap_err(), AggError::NonMonotonic { .. }));
    }

    #[test]
    fn rotate_evicts() {
        let mut a = RateWindowAggregator::new(1000);
        a.record("k", 100).unwrap();
        a.record("k", 200).unwrap();
        a.rotate(5000);
        assert!(a.series.is_empty());
    }

    #[test]
    fn rotate_partial() {
        let mut a = RateWindowAggregator::new(1000);
        a.record("k", 100).unwrap();
        a.record("k", 900).unwrap();
        a.rotate(1500);
        assert_eq!(a.series["k"].len(), 1);
        assert_eq!(a.series["k"][0], 900);
    }

    #[test]
    fn empty_key_rejected() {
        let mut a = RateWindowAggregator::new(1000);
        assert!(matches!(a.record("", 0).unwrap_err(), AggError::EmptyKey));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut a = RateWindowAggregator::new(1000);
        a.schema_version = "9.9.9".into();
        assert!(matches!(a.validate().unwrap_err(), AggError::SchemaMismatch));
    }

    #[test]
    fn agg_serde_roundtrip() {
        let mut a = RateWindowAggregator::new(1000);
        a.record("k", 100).unwrap();
        let j = serde_json::to_string(&a).unwrap();
        let back: RateWindowAggregator = serde_json::from_str(&j).unwrap();
        assert_eq!(a, back);
    }
}
