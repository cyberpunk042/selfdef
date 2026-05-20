//! `selfdef-interval-set` — disjoint integer intervals.
//!
//! Maintains a sorted, merged set of closed intervals [lo, hi]
//! (lo <= hi). insert merges with any overlapping or adjacent
//! interval. contains(x) is a binary search over the sorted set.
//! cover() returns the sum of interval widths (hi - lo + 1).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Closed interval [lo, hi].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Interval {
    /// Low (inclusive).
    pub lo: i64,
    /// High (inclusive).
    pub hi: i64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntervalSet {
    /// Schema version.
    pub schema_version: String,
    /// Sorted, disjoint, non-adjacent intervals.
    pub intervals: Vec<Interval>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum IntervalError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Bad interval.
    #[error("lo must be <= hi")]
    BadInterval,
}

impl IntervalSet {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            intervals: Vec::new(),
        }
    }

    /// Insert interval; merges with overlap/adjacent.
    pub fn insert(&mut self, lo: i64, hi: i64) -> Result<(), IntervalError> {
        if lo > hi { return Err(IntervalError::BadInterval); }
        let mut new_lo = lo;
        let mut new_hi = hi;
        let mut kept: Vec<Interval> = Vec::with_capacity(self.intervals.len() + 1);
        let mut inserted = false;
        for iv in self.intervals.drain(..) {
            // Adjacency: touching when iv.hi + 1 == new_lo or new_hi + 1 == iv.lo.
            let overlap_or_adj = iv.hi.saturating_add(1) >= new_lo && new_hi.saturating_add(1) >= iv.lo;
            if overlap_or_adj {
                new_lo = new_lo.min(iv.lo);
                new_hi = new_hi.max(iv.hi);
            } else if !inserted && iv.lo > new_hi.saturating_add(1) {
                kept.push(Interval { lo: new_lo, hi: new_hi });
                inserted = true;
                kept.push(iv);
            } else {
                kept.push(iv);
            }
        }
        if !inserted {
            kept.push(Interval { lo: new_lo, hi: new_hi });
        }
        self.intervals = kept;
        Ok(())
    }

    /// Contains x?
    pub fn contains(&self, x: i64) -> bool {
        // Binary search for first interval whose hi >= x; check lo <= x.
        let r = self.intervals.binary_search_by(|iv| {
            if iv.hi < x { std::cmp::Ordering::Less }
            else if iv.lo > x { std::cmp::Ordering::Greater }
            else { std::cmp::Ordering::Equal }
        });
        r.is_ok()
    }

    /// Cover (sum of widths).
    pub fn cover(&self) -> u128 {
        self.intervals.iter()
            .map(|iv| (iv.hi as i128 - iv.lo as i128 + 1) as u128)
            .sum()
    }

    /// Count of disjoint intervals.
    pub fn len(&self) -> usize { self.intervals.len() }

    /// Empty.
    pub fn is_empty(&self) -> bool { self.intervals.is_empty() }

    /// Validate.
    pub fn validate(&self) -> Result<(), IntervalError> {
        if self.schema_version != SCHEMA_VERSION { return Err(IntervalError::SchemaMismatch); }
        let mut last_hi: Option<i64> = None;
        for iv in &self.intervals {
            if iv.lo > iv.hi { return Err(IntervalError::BadInterval); }
            if let Some(prev) = last_hi {
                if iv.lo <= prev.saturating_add(1) { return Err(IntervalError::BadInterval); }
            }
            last_hi = Some(iv.hi);
        }
        Ok(())
    }
}

impl Default for IntervalSet {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_contains_nothing() {
        let s = IntervalSet::new();
        assert!(!s.contains(5));
        assert_eq!(s.cover(), 0);
    }

    #[test]
    fn single_interval() {
        let mut s = IntervalSet::new();
        s.insert(10, 20).unwrap();
        assert!(s.contains(15));
        assert!(s.contains(10));
        assert!(s.contains(20));
        assert!(!s.contains(9));
        assert!(!s.contains(21));
        assert_eq!(s.cover(), 11);
    }

    #[test]
    fn disjoint_intervals() {
        let mut s = IntervalSet::new();
        s.insert(10, 20).unwrap();
        s.insert(30, 40).unwrap();
        assert_eq!(s.len(), 2);
        assert!(!s.contains(25));
        assert_eq!(s.cover(), 22);
    }

    #[test]
    fn overlap_merges() {
        let mut s = IntervalSet::new();
        s.insert(10, 20).unwrap();
        s.insert(15, 25).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s.intervals[0], Interval { lo: 10, hi: 25 });
        assert_eq!(s.cover(), 16);
    }

    #[test]
    fn adjacent_merges() {
        let mut s = IntervalSet::new();
        s.insert(10, 20).unwrap();
        s.insert(21, 30).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s.intervals[0], Interval { lo: 10, hi: 30 });
    }

    #[test]
    fn enclosed_interval_no_change() {
        let mut s = IntervalSet::new();
        s.insert(10, 30).unwrap();
        s.insert(15, 20).unwrap();
        assert_eq!(s.intervals[0], Interval { lo: 10, hi: 30 });
    }

    #[test]
    fn bridges_multiple_intervals() {
        let mut s = IntervalSet::new();
        s.insert(10, 20).unwrap();
        s.insert(30, 40).unwrap();
        s.insert(50, 60).unwrap();
        s.insert(15, 55).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s.intervals[0], Interval { lo: 10, hi: 60 });
    }

    #[test]
    fn bad_interval_rejected() {
        let mut s = IntervalSet::new();
        assert!(matches!(s.insert(20, 10).unwrap_err(), IntervalError::BadInterval));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = IntervalSet::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), IntervalError::SchemaMismatch));
    }

    #[test]
    fn set_serde_roundtrip() {
        let mut s = IntervalSet::new();
        s.insert(10, 20).unwrap();
        s.insert(30, 40).unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: IntervalSet = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
