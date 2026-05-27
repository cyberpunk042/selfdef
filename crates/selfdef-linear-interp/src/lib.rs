//! `selfdef-linear-interp` — piecewise-linear interpolation.
//!
//! Points{x, y} strictly increasing x. lookup(x) interpolates
//! between adjacent points (i64 arithmetic via i128 to avoid
//! overflow). Extrapolation: Clamp returns endpoint y; Extend
//! continues the last segment's slope.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Point.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Point {
    /// X.
    pub x: i64,
    /// Y.
    pub y: i64,
}

/// Extrapolation policy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Extrapolation {
    /// Clamp to endpoint y.
    Clamp,
    /// Continue last segment's slope.
    Extend,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinearInterp {
    /// Schema version.
    pub schema_version: String,
    /// Strictly increasing by x.
    pub points: Vec<Point>,
    /// Extrapolation policy.
    pub extrap: Extrapolation,
}

/// Errors.
#[derive(Debug, Error)]
pub enum InterpError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Need points.
    #[error("need at least 2 points")]
    InsufficientPoints,
    /// Not strict.
    #[error("points must be strictly increasing by x")]
    NotStrictlyIncreasing,
}

impl LinearInterp {
    /// New.
    pub fn new(points: Vec<Point>, extrap: Extrapolation) -> Result<Self, InterpError> {
        if points.len() < 2 {
            return Err(InterpError::InsufficientPoints);
        }
        for w in points.windows(2) {
            if w[0].x >= w[1].x {
                return Err(InterpError::NotStrictlyIncreasing);
            }
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            points,
            extrap,
        })
    }

    /// Lookup y at x.
    pub fn lookup(&self, x: i64) -> i64 {
        let first = self.points.first().copied().unwrap();
        let last = self.points.last().copied().unwrap();
        // Extrapolation low.
        if x <= first.x {
            return match self.extrap {
                Extrapolation::Clamp => first.y,
                Extrapolation::Extend => interpolate(self.points[0], self.points[1], x),
            };
        }
        if x >= last.x {
            return match self.extrap {
                Extrapolation::Clamp => last.y,
                Extrapolation::Extend => {
                    let n = self.points.len();
                    interpolate(self.points[n - 2], self.points[n - 1], x)
                }
            };
        }
        // Find segment.
        for w in self.points.windows(2) {
            if x >= w[0].x && x <= w[1].x {
                return interpolate(w[0], w[1], x);
            }
        }
        // Should not reach.
        last.y
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), InterpError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(InterpError::SchemaMismatch);
        }
        if self.points.len() < 2 {
            return Err(InterpError::InsufficientPoints);
        }
        for w in self.points.windows(2) {
            if w[0].x >= w[1].x {
                return Err(InterpError::NotStrictlyIncreasing);
            }
        }
        Ok(())
    }
}

fn interpolate(a: Point, b: Point, x: i64) -> i64 {
    let num = (b.y as i128 - a.y as i128) * (x as i128 - a.x as i128);
    let den = (b.x as i128 - a.x as i128).max(1);
    (a.y as i128 + num / den) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line() -> LinearInterp {
        LinearInterp::new(
            vec![Point { x: 0, y: 0 }, Point { x: 100, y: 100 }],
            Extrapolation::Clamp,
        )
        .unwrap()
    }

    #[test]
    fn linear_midpoint() {
        let l = line();
        assert_eq!(l.lookup(50), 50);
    }

    #[test]
    fn at_endpoints() {
        let l = line();
        assert_eq!(l.lookup(0), 0);
        assert_eq!(l.lookup(100), 100);
    }

    #[test]
    fn clamp_extrapolation() {
        let l = line();
        assert_eq!(l.lookup(-10), 0);
        assert_eq!(l.lookup(200), 100);
    }

    #[test]
    fn extend_extrapolation() {
        let l = LinearInterp::new(
            vec![Point { x: 0, y: 0 }, Point { x: 100, y: 100 }],
            Extrapolation::Extend,
        )
        .unwrap();
        assert_eq!(l.lookup(150), 150);
        assert_eq!(l.lookup(-50), -50);
    }

    #[test]
    fn multi_segment() {
        let l = LinearInterp::new(
            vec![
                Point { x: 0, y: 0 },
                Point { x: 100, y: 100 },
                Point { x: 200, y: 50 },
            ],
            Extrapolation::Clamp,
        )
        .unwrap();
        // Mid of second segment (100..200, y 100 → 50): at x=150 → y=75.
        assert_eq!(l.lookup(150), 75);
    }

    #[test]
    fn insufficient_points_rejected() {
        let r = LinearInterp::new(vec![Point { x: 0, y: 0 }], Extrapolation::Clamp);
        assert!(matches!(r.unwrap_err(), InterpError::InsufficientPoints));
    }

    #[test]
    fn non_strict_rejected() {
        let r = LinearInterp::new(
            vec![Point { x: 0, y: 0 }, Point { x: 0, y: 1 }],
            Extrapolation::Clamp,
        );
        assert!(matches!(r.unwrap_err(), InterpError::NotStrictlyIncreasing));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut l = line();
        l.schema_version = "9.9.9".into();
        assert!(matches!(
            l.validate().unwrap_err(),
            InterpError::SchemaMismatch
        ));
    }

    #[test]
    fn interp_serde_roundtrip() {
        let l = line();
        let j = serde_json::to_string(&l).unwrap();
        let back: LinearInterp = serde_json::from_str(&j).unwrap();
        assert_eq!(l, back);
    }
}
