//! `selfdef-peak-detector` — rolling-window max of i64 samples.
//!
//! observe(value, now_ms) appends and prunes samples older than
//! now - window_ms. current_peak returns the max within window.
//! samples_count returns retained count.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Sample.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Sample {
    /// ts ms.
    pub ts_ms: u64,
    /// value.
    pub value: i64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeakDetector {
    /// Schema version.
    pub schema_version: String,
    /// Window ms.
    pub window_ms: u64,
    /// Retained samples (oldest first).
    pub samples: Vec<Sample>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum PeakError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero window.
    #[error("window_ms must be >= 1")]
    ZeroWindow,
}

impl PeakDetector {
    /// New.
    pub fn new(window_ms: u64) -> Result<Self, PeakError> {
        if window_ms == 0 {
            return Err(PeakError::ZeroWindow);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            window_ms,
            samples: Vec::new(),
        })
    }

    /// Observe; prunes old.
    pub fn observe(&mut self, value: i64, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        self.samples.retain(|s| s.ts_ms >= cutoff);
        self.samples.push(Sample {
            ts_ms: now_ms,
            value,
        });
    }

    /// Peak (max) within current window (None if empty).
    pub fn current_peak(&self, now_ms: u64) -> Option<i64> {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        self.samples
            .iter()
            .filter(|s| s.ts_ms >= cutoff)
            .map(|s| s.value)
            .max()
    }

    /// Retained sample count.
    pub fn samples_count(&self) -> usize {
        self.samples.len()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), PeakError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(PeakError::SchemaMismatch);
        }
        if self.window_ms == 0 {
            return Err(PeakError::ZeroWindow);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_peak_none() {
        let p = PeakDetector::new(1000).unwrap();
        assert!(p.current_peak(0).is_none());
    }

    #[test]
    fn peak_within_window() {
        let mut p = PeakDetector::new(1000).unwrap();
        p.observe(5, 0);
        p.observe(10, 100);
        p.observe(7, 200);
        assert_eq!(p.current_peak(200), Some(10));
    }

    #[test]
    fn old_samples_pruned() {
        let mut p = PeakDetector::new(1000).unwrap();
        p.observe(100, 0);
        p.observe(5, 2000); // observe at 2000 should prune sample at ts=0
        assert_eq!(p.current_peak(2000), Some(5));
        assert_eq!(p.samples_count(), 1);
    }

    #[test]
    fn current_peak_at_later_time() {
        let mut p = PeakDetector::new(500).unwrap();
        p.observe(100, 0);
        p.observe(5, 100);
        // Querying at now=1000 with window=500 → cutoff=500; both samples
        // older than cutoff → no peak.
        assert!(p.current_peak(1000).is_none());
    }

    #[test]
    fn negative_values() {
        let mut p = PeakDetector::new(1000).unwrap();
        p.observe(-10, 0);
        p.observe(-5, 100);
        assert_eq!(p.current_peak(100), Some(-5));
    }

    #[test]
    fn zero_window_rejected() {
        assert!(matches!(
            PeakDetector::new(0).unwrap_err(),
            PeakError::ZeroWindow
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = PeakDetector::new(1000).unwrap();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            PeakError::SchemaMismatch
        ));
    }

    #[test]
    fn detector_serde_roundtrip() {
        let mut p = PeakDetector::new(1000).unwrap();
        p.observe(5, 100);
        let j = serde_json::to_string(&p).unwrap();
        let back: PeakDetector = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
