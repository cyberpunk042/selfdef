//! `selfdef-anomaly-baseline` — sliding mean+stddev anomaly tracker.
//!
//! Records up to `window_size` recent values, computes mean +
//! population stddev, classifies each new observation by |z-score|
//! into Normal / Suspect / Anomalous against per-tier thresholds.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Anomaly tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnomalyTier {
    /// Within baseline.
    Normal,
    /// Suspect (|z| ≥ suspect_z).
    Suspect,
    /// Anomalous (|z| ≥ anomalous_z).
    Anomalous,
}

/// Per-observation result.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct Observation {
    /// Tier.
    pub tier: AnomalyTier,
    /// Z-score (NaN when stddev=0 / sample too small).
    pub z_score: f64,
    /// Sample size at time of observation.
    pub n: u32,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnomalyBaseline {
    /// Schema version.
    pub schema_version: String,
    /// Window size.
    pub window_size: u32,
    /// Minimum sample size before classification kicks in.
    pub min_samples: u32,
    /// |z| threshold for Suspect.
    pub suspect_z: f64,
    /// |z| threshold for Anomalous (must be ≥ suspect_z).
    pub anomalous_z: f64,
    /// Recent samples (FIFO).
    pub samples: Vec<f64>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BaselineError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero window.
    #[error("window_size zero")]
    WindowZero,
    /// min_samples > window.
    #[error("min_samples {0} > window_size {1}")]
    MinExceedsWindow(u32, u32),
    /// Bad thresholds.
    #[error("anomalous_z {anomalous_z} < suspect_z {suspect_z}")]
    BadThresholds {
        /// suspect_z.
        suspect_z: f64,
        /// anomalous_z.
        anomalous_z: f64,
    },
    /// NaN value.
    #[error("value is NaN")]
    NanValue,
}

impl AnomalyBaseline {
    /// New.
    pub fn new(
        window_size: u32,
        min_samples: u32,
        suspect_z: f64,
        anomalous_z: f64,
    ) -> Result<Self, BaselineError> {
        if window_size == 0 {
            return Err(BaselineError::WindowZero);
        }
        if min_samples > window_size {
            return Err(BaselineError::MinExceedsWindow(min_samples, window_size));
        }
        if anomalous_z < suspect_z {
            return Err(BaselineError::BadThresholds {
                suspect_z,
                anomalous_z,
            });
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            window_size,
            min_samples,
            suspect_z,
            anomalous_z,
            samples: Vec::new(),
        })
    }

    /// Observe (records sample + returns classification).
    pub fn observe(&mut self, value: f64) -> Result<Observation, BaselineError> {
        if value.is_nan() {
            return Err(BaselineError::NanValue);
        }
        let (mean, std) = self.stats();
        let n_now = self.samples.len() as u32;
        let z = if std > 0.0 && n_now >= self.min_samples {
            (value - mean) / std
        } else {
            f64::NAN
        };
        let tier = if z.is_nan() {
            AnomalyTier::Normal
        } else if z.abs() >= self.anomalous_z {
            AnomalyTier::Anomalous
        } else if z.abs() >= self.suspect_z {
            AnomalyTier::Suspect
        } else {
            AnomalyTier::Normal
        };
        // Record AFTER classification so we measure against prior baseline.
        self.samples.push(value);
        while (self.samples.len() as u32) > self.window_size {
            self.samples.remove(0);
        }
        Ok(Observation {
            tier,
            z_score: z,
            n: n_now,
        })
    }

    /// Compute (mean, population stddev) of current samples.
    pub fn stats(&self) -> (f64, f64) {
        let n = self.samples.len();
        if n == 0 {
            return (0.0, 0.0);
        }
        let sum: f64 = self.samples.iter().sum();
        let mean = sum / n as f64;
        let var = self.samples.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n as f64;
        (mean, var.sqrt())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BaselineError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BaselineError::SchemaMismatch);
        }
        if self.window_size == 0 {
            return Err(BaselineError::WindowZero);
        }
        if self.min_samples > self.window_size {
            return Err(BaselineError::MinExceedsWindow(
                self.min_samples,
                self.window_size,
            ));
        }
        if self.anomalous_z < self.suspect_z {
            return Err(BaselineError::BadThresholds {
                suspect_z: self.suspect_z,
                anomalous_z: self.anomalous_z,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_window_rejected() {
        assert!(matches!(
            AnomalyBaseline::new(0, 0, 2.0, 4.0).unwrap_err(),
            BaselineError::WindowZero
        ));
    }

    #[test]
    fn min_over_window_rejected() {
        assert!(matches!(
            AnomalyBaseline::new(5, 6, 2.0, 4.0).unwrap_err(),
            BaselineError::MinExceedsWindow(6, 5)
        ));
    }

    #[test]
    fn bad_thresholds_rejected() {
        assert!(matches!(
            AnomalyBaseline::new(5, 1, 4.0, 2.0).unwrap_err(),
            BaselineError::BadThresholds { .. }
        ));
    }

    #[test]
    fn early_observations_normal() {
        let mut b = AnomalyBaseline::new(10, 5, 2.0, 4.0).unwrap();
        for v in [1.0, 2.0, 3.0] {
            let o = b.observe(v).unwrap();
            assert_eq!(o.tier, AnomalyTier::Normal);
        }
    }

    #[test]
    fn stable_samples_stay_normal() {
        let mut b = AnomalyBaseline::new(20, 5, 2.0, 4.0).unwrap();
        for _ in 0..15 {
            b.observe(10.0).unwrap();
        }
        // Zero stddev → NaN z → Normal.
        let o = b.observe(11.0).unwrap();
        assert_eq!(o.tier, AnomalyTier::Normal);
    }

    #[test]
    fn far_outlier_anomalous() {
        let mut b = AnomalyBaseline::new(20, 5, 2.0, 4.0).unwrap();
        for v in [10.0, 11.0, 9.0, 10.5, 9.5, 10.2, 9.8] {
            b.observe(v).unwrap();
        }
        let o = b.observe(100.0).unwrap();
        assert_eq!(o.tier, AnomalyTier::Anomalous);
    }

    #[test]
    fn moderate_outlier_suspect() {
        let mut b = AnomalyBaseline::new(20, 5, 2.0, 5.0).unwrap();
        for v in [10.0, 11.0, 9.0, 10.5, 9.5, 10.2, 9.8] {
            b.observe(v).unwrap();
        }
        let o = b.observe(12.5).unwrap();
        // mean ~ 10, std ~ 0.7. z ~ (12.5-10)/0.7 ~ 3.5. Suspect (>=2, <5).
        assert_eq!(o.tier, AnomalyTier::Suspect);
    }

    #[test]
    fn nan_value_rejected() {
        let mut b = AnomalyBaseline::new(5, 1, 2.0, 4.0).unwrap();
        assert!(matches!(
            b.observe(f64::NAN).unwrap_err(),
            BaselineError::NanValue
        ));
    }

    #[test]
    fn window_evicts_oldest() {
        let mut b = AnomalyBaseline::new(3, 1, 2.0, 4.0).unwrap();
        for v in [1.0, 2.0, 3.0, 4.0, 5.0] {
            b.observe(v).unwrap();
        }
        assert_eq!(b.samples.len(), 3);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut b = AnomalyBaseline::new(5, 1, 2.0, 4.0).unwrap();
        b.schema_version = "9.9.9".into();
        assert!(matches!(
            b.validate().unwrap_err(),
            BaselineError::SchemaMismatch
        ));
    }

    #[test]
    fn tier_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&AnomalyTier::Anomalous).unwrap(),
            "\"anomalous\""
        );
    }

    #[test]
    fn baseline_serde_roundtrip() {
        let mut b = AnomalyBaseline::new(5, 1, 2.0, 4.0).unwrap();
        b.observe(1.0).unwrap();
        let j = serde_json::to_string(&b).unwrap();
        let back: AnomalyBaseline = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
