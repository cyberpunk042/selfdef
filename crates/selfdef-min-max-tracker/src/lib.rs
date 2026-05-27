//! `selfdef-min-max-tracker` — online min/max/mean tracker.
//!
//! observe(value) updates count + sum (i128) + min + max.
//! mean returns sum/count (None if count==0). reset clears.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MinMaxTracker {
    /// Schema version.
    pub schema_version: String,
    /// Count of observed samples.
    pub count: u64,
    /// Sum as i128 (overflow-safe).
    pub sum: i128,
    /// Min (None when count==0).
    pub min: Option<i64>,
    /// Max (None when count==0).
    pub max: Option<i64>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum TrackerError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

impl MinMaxTracker {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            count: 0,
            sum: 0,
            min: None,
            max: None,
        }
    }

    /// Observe a sample.
    pub fn observe(&mut self, value: i64) {
        self.count = self.count.saturating_add(1);
        self.sum += value as i128;
        self.min = Some(match self.min {
            Some(m) => m.min(value),
            None => value,
        });
        self.max = Some(match self.max {
            Some(m) => m.max(value),
            None => value,
        });
    }

    /// Mean (sum/count); None when empty.
    pub fn mean(&self) -> Option<i64> {
        if self.count == 0 {
            return None;
        }
        Some((self.sum / self.count as i128) as i64)
    }

    /// Reset.
    pub fn reset(&mut self) {
        self.count = 0;
        self.sum = 0;
        self.min = None;
        self.max = None;
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), TrackerError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(TrackerError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for MinMaxTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_state() {
        let t = MinMaxTracker::new();
        assert!(t.min.is_none());
        assert!(t.max.is_none());
        assert!(t.mean().is_none());
    }

    #[test]
    fn observe_updates_min_max_mean() {
        let mut t = MinMaxTracker::new();
        for v in [3, 1, 4, 1, 5, 9, 2, 6] {
            t.observe(v);
        }
        assert_eq!(t.min, Some(1));
        assert_eq!(t.max, Some(9));
        assert_eq!(t.count, 8);
        // sum = 31, mean = 3 (integer division).
        assert_eq!(t.mean(), Some(3));
    }

    #[test]
    fn negative_values() {
        let mut t = MinMaxTracker::new();
        t.observe(-5);
        t.observe(5);
        assert_eq!(t.min, Some(-5));
        assert_eq!(t.max, Some(5));
        assert_eq!(t.mean(), Some(0));
    }

    #[test]
    fn reset_clears() {
        let mut t = MinMaxTracker::new();
        t.observe(5);
        t.reset();
        assert_eq!(t.count, 0);
        assert!(t.min.is_none());
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = MinMaxTracker::new();
        t.schema_version = "9.9.9".into();
        assert!(matches!(
            t.validate().unwrap_err(),
            TrackerError::SchemaMismatch
        ));
    }

    #[test]
    fn tracker_serde_roundtrip() {
        let mut t = MinMaxTracker::new();
        t.observe(42);
        let j = serde_json::to_string(&t).unwrap();
        let back: MinMaxTracker = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
