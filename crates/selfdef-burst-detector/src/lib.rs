//! `selfdef-burst-detector` — short-window count-in-window burst.
//!
//! Per (subject, kind), tracks recent event timestamps. `classify`
//! counts in-window observations and emits:
//!   * `Calm` — count < elevated_threshold
//!   * `Elevated { count }` — elevated_threshold ≤ count <
//!     burst_threshold
//!   * `Burst { count, threshold }` — count ≥ burst_threshold
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
pub struct BurstDetector {
    /// Schema version.
    pub schema_version: String,
    /// Window (ms).
    pub window_ms: u64,
    /// Elevated threshold.
    pub elevated_threshold: u32,
    /// Burst threshold.
    pub burst_threshold: u32,
    /// subject → kind → Vec<ts_ms>.
    pub observations: BTreeMap<String, BTreeMap<String, Vec<u64>>>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum BurstVerdict {
    /// Below elevated threshold.
    Calm,
    /// Between elevated and burst thresholds.
    Elevated {
        /// observed count.
        count: u32,
    },
    /// At or above burst threshold.
    Burst {
        /// observed count.
        count: u32,
        /// the burst threshold for reference.
        threshold: u32,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum BurstError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty subject.
    #[error("subject empty")]
    EmptySubject,
    /// Empty kind.
    #[error("kind empty")]
    EmptyKind,
    /// Bad thresholds.
    #[error("elevated_threshold {0} >= burst_threshold {1}")]
    BadThresholds(u32, u32),
}

impl BurstDetector {
    /// New.
    pub fn new(
        window_ms: u64,
        elevated_threshold: u32,
        burst_threshold: u32,
    ) -> Result<Self, BurstError> {
        if elevated_threshold >= burst_threshold {
            return Err(BurstError::BadThresholds(
                elevated_threshold,
                burst_threshold,
            ));
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            window_ms,
            elevated_threshold,
            burst_threshold,
            observations: BTreeMap::new(),
        })
    }

    /// Observe.
    pub fn observe(&mut self, subject: &str, kind: &str, ts_ms: u64) -> Result<(), BurstError> {
        if subject.is_empty() {
            return Err(BurstError::EmptySubject);
        }
        if kind.is_empty() {
            return Err(BurstError::EmptyKind);
        }
        self.observations
            .entry(subject.into())
            .or_default()
            .entry(kind.into())
            .or_default()
            .push(ts_ms);
        Ok(())
    }

    /// Classify count in window.
    pub fn classify(&self, subject: &str, kind: &str, now_ms: u64) -> BurstVerdict {
        let count = self
            .observations
            .get(subject)
            .and_then(|m| m.get(kind))
            .map(|v| {
                let cutoff = now_ms.saturating_sub(self.window_ms);
                v.iter().filter(|t| **t >= cutoff && **t <= now_ms).count() as u32
            })
            .unwrap_or(0);
        if count >= self.burst_threshold {
            BurstVerdict::Burst {
                count,
                threshold: self.burst_threshold,
            }
        } else if count >= self.elevated_threshold {
            BurstVerdict::Elevated { count }
        } else {
            BurstVerdict::Calm
        }
    }

    /// Rotate (drop out-of-window).
    pub fn rotate(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        for (_, m) in self.observations.iter_mut() {
            for v in m.values_mut() {
                v.retain(|t| *t >= cutoff);
            }
            m.retain(|_, v| !v.is_empty());
        }
        self.observations.retain(|_, m| !m.is_empty());
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BurstError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BurstError::SchemaMismatch);
        }
        if self.elevated_threshold >= self.burst_threshold {
            return Err(BurstError::BadThresholds(
                self.elevated_threshold,
                self.burst_threshold,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_thresholds_rejected() {
        assert!(matches!(
            BurstDetector::new(1000, 10, 5).unwrap_err(),
            BurstError::BadThresholds(_, _)
        ));
    }

    #[test]
    fn calm_under_thresholds() {
        let mut b = BurstDetector::new(1000, 2, 4).unwrap();
        b.observe("s", "k", 0).unwrap();
        assert_eq!(b.classify("s", "k", 500), BurstVerdict::Calm);
    }

    #[test]
    fn elevated_band() {
        let mut b = BurstDetector::new(1000, 2, 4).unwrap();
        for i in 0..3 {
            b.observe("s", "k", i * 100).unwrap();
        }
        match b.classify("s", "k", 500) {
            BurstVerdict::Elevated { count } => assert_eq!(count, 3),
            _ => panic!(),
        }
    }

    #[test]
    fn burst_band() {
        let mut b = BurstDetector::new(1000, 2, 4).unwrap();
        for i in 0..5 {
            b.observe("s", "k", i * 100).unwrap();
        }
        match b.classify("s", "k", 500) {
            BurstVerdict::Burst { count, threshold } => {
                assert_eq!(count, 5);
                assert_eq!(threshold, 4);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn out_of_window_excluded() {
        let mut b = BurstDetector::new(1000, 2, 4).unwrap();
        for i in 0..5 {
            b.observe("s", "k", i * 100).unwrap();
        }
        // Far in the future.
        assert_eq!(b.classify("s", "k", 1_000_000), BurstVerdict::Calm);
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut b = BurstDetector::new(1000, 2, 4).unwrap();
        assert!(matches!(
            b.observe("", "k", 0).unwrap_err(),
            BurstError::EmptySubject
        ));
        assert!(matches!(
            b.observe("s", "", 0).unwrap_err(),
            BurstError::EmptyKind
        ));
    }

    #[test]
    fn rotate_drops_stale() {
        let mut b = BurstDetector::new(1000, 2, 4).unwrap();
        b.observe("s", "k", 0).unwrap();
        b.rotate(10_000);
        assert!(b.observations.is_empty());
    }

    #[test]
    fn schema_drift_rejected() {
        let mut b = BurstDetector::new(1000, 2, 4).unwrap();
        b.schema_version = "9.9.9".into();
        assert!(matches!(
            b.validate().unwrap_err(),
            BurstError::SchemaMismatch
        ));
    }

    #[test]
    fn burst_serde_roundtrip() {
        let mut b = BurstDetector::new(1000, 2, 4).unwrap();
        b.observe("s", "k", 0).unwrap();
        let j = serde_json::to_string(&b).unwrap();
        let back: BurstDetector = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
