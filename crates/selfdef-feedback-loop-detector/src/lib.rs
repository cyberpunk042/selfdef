//! `selfdef-feedback-loop-detector` — repetition + feedback detector.
//!
//! Tracks edges (tool_id, input_digest, output_digest). Reports
//! `CycleDetected` when the exact edge appears ≥ repeat_threshold
//! times within `window_size`. Reports `FeedbackDetected` when a
//! new output_digest equals a previous input_digest (loop where
//! output is being re-fed as input).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One observed edge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Edge {
    /// Tool id.
    pub tool_id: String,
    /// Input digest.
    pub input_digest: u64,
    /// Output digest.
    pub output_digest: u64,
}

/// Observation outcome.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Observation {
    /// No issue.
    Clean,
    /// Same edge repeated >= threshold within window.
    CycleDetected {
        /// edge.
        edge: Edge,
        /// count.
        count: u32,
    },
    /// Output equals a previous input (feedback loop).
    FeedbackDetected {
        /// digest of feedback.
        digest: u64,
        /// edge that produced it.
        edge: Edge,
    },
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeedbackLoopDetector {
    /// Schema version.
    pub schema_version: String,
    /// Window size.
    pub window_size: u32,
    /// Edge-repeat threshold.
    pub repeat_threshold: u32,
    /// FIFO of recent edges.
    pub recent: Vec<Edge>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DetectorError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero window.
    #[error("window_size is zero")]
    WindowZero,
    /// Zero threshold.
    #[error("repeat_threshold is zero")]
    ThresholdZero,
}

impl FeedbackLoopDetector {
    /// New.
    pub fn new(window_size: u32, repeat_threshold: u32) -> Result<Self, DetectorError> {
        if window_size == 0 { return Err(DetectorError::WindowZero); }
        if repeat_threshold == 0 { return Err(DetectorError::ThresholdZero); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            window_size,
            repeat_threshold,
            recent: Vec::new(),
        })
    }

    /// Observe one edge.
    pub fn observe(&mut self, edge: Edge) -> Observation {
        // FeedbackDetected: new output digest equals a previous input digest.
        if let Some(prev) = self.recent.iter().find(|e| e.input_digest == edge.output_digest).cloned() {
            // Insert before reporting so it shows in count next round.
            self.recent.push(edge.clone());
            while (self.recent.len() as u32) > self.window_size {
                self.recent.remove(0);
            }
            return Observation::FeedbackDetected {
                digest: edge.output_digest,
                edge: prev,
            };
        }
        self.recent.push(edge.clone());
        while (self.recent.len() as u32) > self.window_size {
            self.recent.remove(0);
        }
        let count = self.recent.iter().filter(|e| **e == edge).count() as u32;
        if count >= self.repeat_threshold {
            return Observation::CycleDetected { edge, count };
        }
        Observation::Clean
    }

    /// Clear ring.
    pub fn reset(&mut self) {
        self.recent.clear();
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DetectorError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(DetectorError::SchemaMismatch);
        }
        if self.window_size == 0 { return Err(DetectorError::WindowZero); }
        if self.repeat_threshold == 0 { return Err(DetectorError::ThresholdZero); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(tool: &str, ind: u64, outd: u64) -> Edge {
        Edge { tool_id: tool.into(), input_digest: ind, output_digest: outd }
    }

    #[test]
    fn zero_window_rejected() {
        assert!(matches!(FeedbackLoopDetector::new(0, 1).unwrap_err(), DetectorError::WindowZero));
    }

    #[test]
    fn zero_threshold_rejected() {
        assert!(matches!(FeedbackLoopDetector::new(5, 0).unwrap_err(), DetectorError::ThresholdZero));
    }

    #[test]
    fn clean_when_distinct() {
        let mut d = FeedbackLoopDetector::new(5, 3).unwrap();
        assert!(matches!(d.observe(e("a", 1, 2)), Observation::Clean));
        assert!(matches!(d.observe(e("b", 3, 4)), Observation::Clean));
    }

    #[test]
    fn cycle_detected_at_threshold() {
        let mut d = FeedbackLoopDetector::new(5, 2).unwrap();
        d.observe(e("a", 1, 2));
        match d.observe(e("a", 1, 2)) {
            Observation::CycleDetected { count, .. } => assert_eq!(count, 2),
            _ => panic!(),
        }
    }

    #[test]
    fn feedback_detected_when_output_matches_prior_input() {
        let mut d = FeedbackLoopDetector::new(10, 5).unwrap();
        d.observe(e("a", 100, 200));
        match d.observe(e("b", 50, 100)) {
            Observation::FeedbackDetected { digest, .. } => assert_eq!(digest, 100),
            _ => panic!(),
        }
    }

    #[test]
    fn window_evicts_old_edges() {
        let mut d = FeedbackLoopDetector::new(2, 2).unwrap();
        d.observe(e("a", 1, 2));
        d.observe(e("b", 3, 4));
        d.observe(e("c", 5, 6));
        // a should be evicted.
        let obs = d.observe(e("a", 1, 2));
        // count should be 1 now (no cycle).
        assert!(matches!(obs, Observation::Clean));
    }

    #[test]
    fn reset_clears_recent() {
        let mut d = FeedbackLoopDetector::new(5, 2).unwrap();
        d.observe(e("a", 1, 2));
        d.observe(e("a", 1, 2));
        d.reset();
        assert!(matches!(d.observe(e("a", 1, 2)), Observation::Clean));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut d = FeedbackLoopDetector::new(5, 2).unwrap();
        d.schema_version = "9.9.9".into();
        assert!(matches!(d.validate().unwrap_err(), DetectorError::SchemaMismatch));
    }

    #[test]
    fn observation_serde_kebab() {
        let o = Observation::Clean;
        assert!(serde_json::to_string(&o).unwrap().contains("\"kind\":\"clean\""));
        let o = Observation::CycleDetected { edge: e("a", 1, 2), count: 3 };
        assert!(serde_json::to_string(&o).unwrap().contains("\"kind\":\"cycle-detected\""));
    }

    #[test]
    fn detector_serde_roundtrip() {
        let mut d = FeedbackLoopDetector::new(5, 2).unwrap();
        d.observe(e("a", 1, 2));
        let j = serde_json::to_string(&d).unwrap();
        let back: FeedbackLoopDetector = serde_json::from_str(&j).unwrap();
        assert_eq!(d, back);
    }
}
