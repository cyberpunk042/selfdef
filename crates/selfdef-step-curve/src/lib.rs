//! `selfdef-step-curve` — piecewise step lookup.
//!
//! Construct from sorted (x, y) pairs (strictly increasing x).
//! lookup(x) returns y of the highest x_i ≤ x (or default if
//! x < first). Useful for stair-step policy curves (e.g.,
//! threshold → action).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Step.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Step {
    /// X.
    pub x: i64,
    /// Y.
    pub y: i64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StepCurve {
    /// Schema version.
    pub schema_version: String,
    /// Strictly-increasing-by-x steps.
    pub steps: Vec<Step>,
    /// Default y (returned when x < first step).
    pub default_y: i64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CurveError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Bad order.
    #[error("steps must be strictly increasing by x")]
    NotStrictlyIncreasing,
}

impl StepCurve {
    /// New from steps.
    pub fn new(steps: Vec<Step>, default_y: i64) -> Result<Self, CurveError> {
        for w in steps.windows(2) {
            if w[0].x >= w[1].x { return Err(CurveError::NotStrictlyIncreasing); }
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            steps,
            default_y,
        })
    }

    /// Lookup y for x.
    pub fn lookup(&self, x: i64) -> i64 {
        if self.steps.is_empty() || x < self.steps[0].x {
            return self.default_y;
        }
        // Binary-search rightmost step.x <= x.
        let mut lo = 0usize;
        let mut hi = self.steps.len();
        while lo < hi {
            let m = (lo + hi) / 2;
            if self.steps[m].x <= x { lo = m + 1; }
            else { hi = m; }
        }
        self.steps[lo - 1].y
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CurveError> {
        if self.schema_version != SCHEMA_VERSION { return Err(CurveError::SchemaMismatch); }
        for w in self.steps.windows(2) {
            if w[0].x >= w[1].x { return Err(CurveError::NotStrictlyIncreasing); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn curve() -> StepCurve {
        StepCurve::new(
            vec![
                Step { x: 10, y: 1 },
                Step { x: 50, y: 5 },
                Step { x: 100, y: 10 },
            ],
            0,
        ).unwrap()
    }

    #[test]
    fn below_first_returns_default() {
        let c = curve();
        assert_eq!(c.lookup(0), 0);
        assert_eq!(c.lookup(9), 0);
    }

    #[test]
    fn at_step_boundary() {
        let c = curve();
        assert_eq!(c.lookup(10), 1);
        assert_eq!(c.lookup(50), 5);
        assert_eq!(c.lookup(100), 10);
    }

    #[test]
    fn between_steps() {
        let c = curve();
        assert_eq!(c.lookup(25), 1);
        assert_eq!(c.lookup(75), 5);
        assert_eq!(c.lookup(9999), 10);
    }

    #[test]
    fn empty_steps_returns_default() {
        let c = StepCurve::new(vec![], 42).unwrap();
        assert_eq!(c.lookup(100), 42);
    }

    #[test]
    fn non_strict_x_rejected() {
        let r = StepCurve::new(
            vec![Step { x: 10, y: 1 }, Step { x: 10, y: 2 }],
            0,
        );
        assert!(matches!(r.unwrap_err(), CurveError::NotStrictlyIncreasing));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = curve();
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), CurveError::SchemaMismatch));
    }

    #[test]
    fn curve_serde_roundtrip() {
        let c = curve();
        let j = serde_json::to_string(&c).unwrap();
        let back: StepCurve = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
