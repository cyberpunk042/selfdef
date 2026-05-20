//! `selfdef-linear-regression` — OLS slope/intercept from sums.
//!
//! observe(x, y) accumulates count, Σx, Σy, Σxy, Σx² (i128).
//! slope_micro = (n*Σxy - Σx*Σy) * 1_000_000 / (n*Σx² - Σx²);
//! intercept_micro = (Σy - slope*Σx) * 1_000_000 / n.
//! Errors when denom == 0 (all-x equal or zero observations).
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
pub struct LinearRegression {
    /// Schema version.
    pub schema_version: String,
    /// Observations.
    pub n: u64,
    /// Σx.
    pub sum_x: i128,
    /// Σy.
    pub sum_y: i128,
    /// Σxy.
    pub sum_xy: i128,
    /// Σx².
    pub sum_xx: i128,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RegError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Insufficient observations / degenerate.
    #[error("need >=2 distinct-x observations")]
    Degenerate,
}

impl LinearRegression {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            n: 0,
            sum_x: 0,
            sum_y: 0,
            sum_xy: 0,
            sum_xx: 0,
        }
    }

    /// Observe.
    pub fn observe(&mut self, x: i64, y: i64) {
        self.n = self.n.saturating_add(1);
        self.sum_x += x as i128;
        self.sum_y += y as i128;
        self.sum_xy += x as i128 * y as i128;
        self.sum_xx += x as i128 * x as i128;
    }

    /// Slope in micro units (slope * 1_000_000 to keep integer precision).
    pub fn slope_micro(&self) -> Result<i64, RegError> {
        if self.n < 2 { return Err(RegError::Degenerate); }
        let n = self.n as i128;
        let denom = n * self.sum_xx - self.sum_x * self.sum_x;
        if denom == 0 { return Err(RegError::Degenerate); }
        let num = n * self.sum_xy - self.sum_x * self.sum_y;
        Ok(((num * 1_000_000) / denom) as i64)
    }

    /// Intercept in micro units.
    pub fn intercept_micro(&self) -> Result<i64, RegError> {
        if self.n == 0 { return Err(RegError::Degenerate); }
        let slope_u = self.slope_micro()?;
        let n = self.n as i128;
        // intercept = (sum_y - slope*sum_x) / n; we want micro.
        let intercept_num = (self.sum_y - (slope_u as i128 * self.sum_x) / 1_000_000) * 1_000_000;
        Ok((intercept_num / n) as i64)
    }

    /// Reset.
    pub fn reset(&mut self) {
        self.n = 0;
        self.sum_x = 0;
        self.sum_y = 0;
        self.sum_xy = 0;
        self.sum_xx = 0;
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RegError> {
        if self.schema_version != SCHEMA_VERSION { return Err(RegError::SchemaMismatch); }
        Ok(())
    }
}

impl Default for LinearRegression {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_obs_degenerate() {
        let mut r = LinearRegression::new();
        r.observe(0, 0);
        assert!(matches!(r.slope_micro().unwrap_err(), RegError::Degenerate));
    }

    #[test]
    fn all_x_same_degenerate() {
        let mut r = LinearRegression::new();
        r.observe(5, 1);
        r.observe(5, 2);
        r.observe(5, 3);
        assert!(matches!(r.slope_micro().unwrap_err(), RegError::Degenerate));
    }

    #[test]
    fn perfect_line() {
        let mut r = LinearRegression::new();
        // y = 2x + 1.
        for x in 0..5 { r.observe(x as i64, 2 * x + 1); }
        // Slope = 2 → 2_000_000 micro; intercept = 1 → 1_000_000.
        assert_eq!(r.slope_micro().unwrap(), 2_000_000);
        let intc = r.intercept_micro().unwrap();
        assert!((intc - 1_000_000).abs() < 10, "intercept = {}", intc);
    }

    #[test]
    fn negative_slope() {
        let mut r = LinearRegression::new();
        // y = -3x + 5.
        for x in 0..5 { r.observe(x as i64, -3 * x + 5); }
        assert_eq!(r.slope_micro().unwrap(), -3_000_000);
    }

    #[test]
    fn reset_clears() {
        let mut r = LinearRegression::new();
        r.observe(0, 0);
        r.observe(1, 1);
        r.reset();
        assert_eq!(r.n, 0);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = LinearRegression::new();
        r.schema_version = "9.9.9".into();
        assert!(matches!(r.validate().unwrap_err(), RegError::SchemaMismatch));
    }

    #[test]
    fn reg_serde_roundtrip() {
        let mut r = LinearRegression::new();
        r.observe(1, 2);
        let j = serde_json::to_string(&r).unwrap();
        let back: LinearRegression = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
