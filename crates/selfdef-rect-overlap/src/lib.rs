//! `selfdef-rect-overlap` — 2D integer rectangle ops.
//!
//! Rect{x, y, w, h} (w,h > 0). intersect → Option<Rect>;
//! bounding_box → smallest enclosing rect; contains_point /
//! contains_rect; area.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Rectangle.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rect {
    /// Top-left x.
    pub x: i64,
    /// Top-left y.
    pub y: i64,
    /// Width (>=1).
    pub w: i64,
    /// Height (>=1).
    pub h: i64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RectError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Bad dims.
    #[error("w and h must be >= 1")]
    BadDims,
}

impl Rect {
    /// New (validates dims).
    pub fn new(x: i64, y: i64, w: i64, h: i64) -> Result<Self, RectError> {
        if w < 1 || h < 1 {
            return Err(RectError::BadDims);
        }
        Ok(Self { x, y, w, h })
    }

    /// Right edge (exclusive).
    pub fn right(&self) -> i64 {
        self.x + self.w
    }
    /// Bottom edge (exclusive).
    pub fn bottom(&self) -> i64 {
        self.y + self.h
    }
    /// Area.
    pub fn area(&self) -> i128 {
        self.w as i128 * self.h as i128
    }

    /// Intersect with other.
    pub fn intersect(&self, other: &Rect) -> Option<Rect> {
        let lo_x = self.x.max(other.x);
        let lo_y = self.y.max(other.y);
        let hi_x = self.right().min(other.right());
        let hi_y = self.bottom().min(other.bottom());
        if hi_x > lo_x && hi_y > lo_y {
            Rect::new(lo_x, lo_y, hi_x - lo_x, hi_y - lo_y).ok()
        } else {
            None
        }
    }

    /// Bounding box (smallest rect containing both).
    pub fn bounding_box(&self, other: &Rect) -> Rect {
        let lo_x = self.x.min(other.x);
        let lo_y = self.y.min(other.y);
        let hi_x = self.right().max(other.right());
        let hi_y = self.bottom().max(other.bottom());
        Rect {
            x: lo_x,
            y: lo_y,
            w: hi_x - lo_x,
            h: hi_y - lo_y,
        }
    }

    /// Contains point?
    pub fn contains_point(&self, x: i64, y: i64) -> bool {
        x >= self.x && x < self.right() && y >= self.y && y < self.bottom()
    }

    /// Contains other rect?
    pub fn contains_rect(&self, other: &Rect) -> bool {
        other.x >= self.x
            && other.y >= self.y
            && other.right() <= self.right()
            && other.bottom() <= self.bottom()
    }
}

/// Versioned wrapper.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RectState {
    /// Schema version.
    pub schema_version: String,
}

impl RectState {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RectError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RectError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for RectState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intersect_overlap() {
        let a = Rect::new(0, 0, 10, 10).unwrap();
        let b = Rect::new(5, 5, 10, 10).unwrap();
        let i = a.intersect(&b).unwrap();
        assert_eq!(
            i,
            Rect {
                x: 5,
                y: 5,
                w: 5,
                h: 5
            }
        );
    }

    #[test]
    fn intersect_disjoint() {
        let a = Rect::new(0, 0, 5, 5).unwrap();
        let b = Rect::new(100, 100, 5, 5).unwrap();
        assert!(a.intersect(&b).is_none());
    }

    #[test]
    fn intersect_edge_touch() {
        // Touch on edge → no interior overlap.
        let a = Rect::new(0, 0, 5, 5).unwrap();
        let b = Rect::new(5, 0, 5, 5).unwrap();
        assert!(a.intersect(&b).is_none());
    }

    #[test]
    fn bounding_box_union() {
        let a = Rect::new(0, 0, 5, 5).unwrap();
        let b = Rect::new(10, 10, 5, 5).unwrap();
        let bb = a.bounding_box(&b);
        assert_eq!(
            bb,
            Rect {
                x: 0,
                y: 0,
                w: 15,
                h: 15
            }
        );
    }

    #[test]
    fn contains_point_basic() {
        let r = Rect::new(0, 0, 10, 10).unwrap();
        assert!(r.contains_point(0, 0));
        assert!(r.contains_point(9, 9));
        assert!(!r.contains_point(10, 10));
    }

    #[test]
    fn contains_rect_basic() {
        let a = Rect::new(0, 0, 10, 10).unwrap();
        let b = Rect::new(2, 2, 5, 5).unwrap();
        let c = Rect::new(9, 9, 5, 5).unwrap();
        assert!(a.contains_rect(&b));
        assert!(!a.contains_rect(&c));
    }

    #[test]
    fn area() {
        let a = Rect::new(0, 0, 4, 3).unwrap();
        assert_eq!(a.area(), 12);
    }

    #[test]
    fn bad_dims_rejected() {
        assert!(matches!(
            Rect::new(0, 0, 0, 5).unwrap_err(),
            RectError::BadDims
        ));
        assert!(matches!(
            Rect::new(0, 0, 5, 0).unwrap_err(),
            RectError::BadDims
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = RectState::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            RectError::SchemaMismatch
        ));
    }

    #[test]
    fn state_serde_roundtrip() {
        let s = RectState::new();
        let j = serde_json::to_string(&s).unwrap();
        let back: RectState = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
