//! `selfdef-prompt-output-similarity` — mode-collapse detector.
//!
//! Bounded ring of FNV-1a digests of recent outputs. observe(text)
//! reports CollisionDetected when the new digest already appears ≥
//! `collision_threshold` times in the last `window_size` entries.
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
pub struct PromptOutputSimilarity {
    /// Schema version.
    pub schema_version: String,
    /// Window size (ring buffer).
    pub window_size: u32,
    /// Min repeated count within window to trip.
    pub collision_threshold: u32,
    /// FIFO of recent digests.
    pub recent: Vec<u64>,
}

/// Decision.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Observation {
    /// Output recorded, no collision.
    Distinct {
        /// digest.
        digest: u64,
    },
    /// Collision tripped (count within window >= threshold).
    CollisionDetected {
        /// digest.
        digest: u64,
        /// count.
        count: u32,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum SimilarityError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// window_size zero.
    #[error("window_size is zero")]
    WindowZero,
    /// collision_threshold zero.
    #[error("collision_threshold is zero")]
    ThresholdZero,
    /// threshold > window.
    #[error("collision_threshold {0} > window_size {1}")]
    ThresholdExceedsWindow(u32, u32),
}

impl PromptOutputSimilarity {
    /// New.
    pub fn new(window_size: u32, collision_threshold: u32) -> Result<Self, SimilarityError> {
        if window_size == 0 { return Err(SimilarityError::WindowZero); }
        if collision_threshold == 0 { return Err(SimilarityError::ThresholdZero); }
        if collision_threshold > window_size {
            return Err(SimilarityError::ThresholdExceedsWindow(collision_threshold, window_size));
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            window_size,
            collision_threshold,
            recent: Vec::new(),
        })
    }

    /// Observe.
    pub fn observe(&mut self, text: &str) -> Observation {
        let digest = fnv1a_64(text.as_bytes());
        // Push first so we observe within updated window.
        self.recent.push(digest);
        while (self.recent.len() as u32) > self.window_size {
            self.recent.remove(0);
        }
        let count = self.recent.iter().filter(|&&d| d == digest).count() as u32;
        if count >= self.collision_threshold {
            Observation::CollisionDetected { digest, count }
        } else {
            Observation::Distinct { digest }
        }
    }

    /// Clear ring.
    pub fn reset(&mut self) {
        self.recent.clear();
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), SimilarityError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SimilarityError::SchemaMismatch);
        }
        if self.window_size == 0 { return Err(SimilarityError::WindowZero); }
        if self.collision_threshold == 0 { return Err(SimilarityError::ThresholdZero); }
        if self.collision_threshold > self.window_size {
            return Err(SimilarityError::ThresholdExceedsWindow(self.collision_threshold, self.window_size));
        }
        Ok(())
    }
}

fn fnv1a_64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_window_rejected() {
        assert!(matches!(PromptOutputSimilarity::new(0, 1).unwrap_err(), SimilarityError::WindowZero));
    }

    #[test]
    fn zero_threshold_rejected() {
        assert!(matches!(PromptOutputSimilarity::new(5, 0).unwrap_err(), SimilarityError::ThresholdZero));
    }

    #[test]
    fn threshold_over_window_rejected() {
        assert!(matches!(
            PromptOutputSimilarity::new(3, 5).unwrap_err(),
            SimilarityError::ThresholdExceedsWindow(5, 3)
        ));
    }

    #[test]
    fn distinct_returns_distinct() {
        let mut s = PromptOutputSimilarity::new(5, 2).unwrap();
        assert!(matches!(s.observe("a"), Observation::Distinct { .. }));
        assert!(matches!(s.observe("b"), Observation::Distinct { .. }));
    }

    #[test]
    fn collision_trips_when_threshold_met() {
        let mut s = PromptOutputSimilarity::new(5, 2).unwrap();
        s.observe("a");
        match s.observe("a") {
            Observation::CollisionDetected { count, .. } => assert_eq!(count, 2),
            _ => panic!(),
        }
    }

    #[test]
    fn window_eviction_clears_old_collisions() {
        let mut s = PromptOutputSimilarity::new(2, 2).unwrap();
        s.observe("a");
        s.observe("b");
        s.observe("b"); // 2 b's in window of 2 -> collision.
        // Now push new -> window slides forward.
        let _ = s.observe("c");
        // 'a' is gone; 'c' first occurrence.
        match s.observe("c") {
            Observation::CollisionDetected { .. } => {}
            _ => panic!("c should collide now"),
        }
    }

    #[test]
    fn reset_clears() {
        let mut s = PromptOutputSimilarity::new(5, 2).unwrap();
        s.observe("a");
        s.observe("a");
        s.reset();
        assert!(matches!(s.observe("a"), Observation::Distinct { .. }));
    }

    #[test]
    fn distinct_inputs_no_collision() {
        let mut s = PromptOutputSimilarity::new(10, 2).unwrap();
        for i in 0..10 {
            let obs = s.observe(&format!("output-{i}"));
            assert!(matches!(obs, Observation::Distinct { .. }));
        }
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = PromptOutputSimilarity::new(5, 2).unwrap();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), SimilarityError::SchemaMismatch));
    }

    #[test]
    fn observation_serde_kebab() {
        let o = Observation::CollisionDetected { digest: 1, count: 2 };
        let j = serde_json::to_string(&o).unwrap();
        assert!(j.contains("\"kind\":\"collision-detected\""));
    }

    #[test]
    fn state_serde_roundtrip() {
        let mut s = PromptOutputSimilarity::new(5, 2).unwrap();
        s.observe("hi");
        let j = serde_json::to_string(&s).unwrap();
        let back: PromptOutputSimilarity = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
