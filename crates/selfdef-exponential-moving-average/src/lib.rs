//! `selfdef-exponential-moving-average` — EMA smoother.
//!
//! alpha_bp in 1..=10000 (basis points). First sample seeds the
//! EMA. Subsequent samples: ema = (alpha * sample + (10000-alpha) * ema)
//! / 10000. Carries fractional state internally as i128
//! scaled by 10000 to avoid drift.
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
pub struct ExponentialMovingAverage {
    /// Schema version.
    pub schema_version: String,
    /// Smoothing factor in basis points (1..=10000).
    pub alpha_bp: u32,
    /// EMA value × 10000 (None = not yet seeded).
    pub scaled_ema: Option<i128>,
    /// Samples observed.
    pub samples: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum EmaError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Bad alpha.
    #[error("alpha_bp must be 1..=10000")]
    BadAlpha,
}

impl ExponentialMovingAverage {
    /// New.
    pub fn new(alpha_bp: u32) -> Result<Self, EmaError> {
        if alpha_bp == 0 || alpha_bp > 10000 {
            return Err(EmaError::BadAlpha);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            alpha_bp,
            scaled_ema: None,
            samples: 0,
        })
    }

    /// Observe a sample.
    pub fn observe(&mut self, sample: i64) {
        let alpha = self.alpha_bp as i128;
        let one_minus = 10_000i128 - alpha;
        let sample_scaled = (sample as i128) * 10_000;
        self.scaled_ema = Some(match self.scaled_ema {
            None => sample_scaled,
            Some(prev) => {
                // (alpha * sample + (10000-alpha) * prev/10000) / 10000
                // We carry prev as already-scaled (ema*10000). To keep
                // dimensions: new_scaled = (alpha*sample_scaled + one_minus*prev) / 10000
                (alpha * sample_scaled + one_minus * prev) / 10_000
            }
        });
        self.samples = self.samples.saturating_add(1);
    }

    /// Current EMA (rounded to nearest i64).
    pub fn value(&self) -> Option<i64> {
        self.scaled_ema.map(|s| {
            // Round half away from zero.
            let half = if s >= 0 { 5_000i128 } else { -5_000i128 };
            ((s + half) / 10_000) as i64
        })
    }

    /// Reset state.
    pub fn reset(&mut self) {
        self.scaled_ema = None;
        self.samples = 0;
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), EmaError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(EmaError::SchemaMismatch);
        }
        if self.alpha_bp == 0 || self.alpha_bp > 10000 {
            return Err(EmaError::BadAlpha);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sample_seeds() {
        let mut e = ExponentialMovingAverage::new(5000).unwrap();
        e.observe(100);
        assert_eq!(e.value(), Some(100));
    }

    #[test]
    fn alpha_full_tracks_sample() {
        let mut e = ExponentialMovingAverage::new(10000).unwrap();
        e.observe(10);
        e.observe(20);
        e.observe(30);
        assert_eq!(e.value(), Some(30));
    }

    #[test]
    fn alpha_half_averages() {
        let mut e = ExponentialMovingAverage::new(5000).unwrap();
        e.observe(0);
        e.observe(100);
        // (0.5*100 + 0.5*0) = 50
        assert_eq!(e.value(), Some(50));
        e.observe(100);
        // (0.5*100 + 0.5*50) = 75
        assert_eq!(e.value(), Some(75));
    }

    #[test]
    fn alpha_low_resists_change() {
        let mut e = ExponentialMovingAverage::new(100).unwrap(); // 1%
        e.observe(0);
        for _ in 0..10 {
            e.observe(1000);
        }
        let v = e.value().unwrap();
        // After 10 steps at alpha=0.01, ema ≈ 1000*(1-0.99^10) ≈ 1000*0.0956 ≈ 96
        assert!((50..=120).contains(&v), "got {v}");
    }

    #[test]
    fn negative_samples() {
        let mut e = ExponentialMovingAverage::new(5000).unwrap();
        e.observe(-100);
        e.observe(100);
        assert_eq!(e.value(), Some(0));
    }

    #[test]
    fn reset_clears() {
        let mut e = ExponentialMovingAverage::new(5000).unwrap();
        e.observe(50);
        e.reset();
        assert_eq!(e.value(), None);
        assert_eq!(e.samples, 0);
    }

    #[test]
    fn empty_value_none() {
        let e = ExponentialMovingAverage::new(5000).unwrap();
        assert_eq!(e.value(), None);
    }

    #[test]
    fn bad_alpha_rejected() {
        assert!(matches!(
            ExponentialMovingAverage::new(0).unwrap_err(),
            EmaError::BadAlpha
        ));
        assert!(matches!(
            ExponentialMovingAverage::new(10001).unwrap_err(),
            EmaError::BadAlpha
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut e = ExponentialMovingAverage::new(5000).unwrap();
        e.schema_version = "9.9.9".into();
        assert!(matches!(
            e.validate().unwrap_err(),
            EmaError::SchemaMismatch
        ));
    }

    #[test]
    fn ema_serde_roundtrip() {
        let mut e = ExponentialMovingAverage::new(5000).unwrap();
        e.observe(42);
        let j = serde_json::to_string(&e).unwrap();
        let back: ExponentialMovingAverage = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }
}
