//! `selfdef-count-min-sketch` — approximate frequency counter.
//!
//! d rows × w columns of u64 cells. add(key, n) hashes key into
//! d distinct columns and adds n to each. estimate(key) returns
//! the minimum across the d cells (the CM upper-bound estimate).
//! Row hashes derived from FNV-1a-64 + per-row seed.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Sketch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CountMinSketch {
    /// Schema version.
    pub schema_version: String,
    /// Row count (depth).
    pub depth: u32,
    /// Column count (width).
    pub width: u32,
    /// depth*width cells in row-major order.
    pub cells: Vec<u64>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CmsError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero geometry.
    #[error("depth and width must be >= 1")]
    ZeroDim,
    /// Geometry mismatch.
    #[error("cells length must equal depth*width")]
    BadCells,
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

impl CountMinSketch {
    /// New.
    pub fn new(depth: u32, width: u32) -> Result<Self, CmsError> {
        if depth == 0 || width == 0 {
            return Err(CmsError::ZeroDim);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            depth,
            width,
            cells: vec![0; (depth as usize) * (width as usize)],
        })
    }

    fn col(&self, row: u32, key: &str) -> usize {
        // Per-row seed mixed in as ASCII decimal prefix.
        let mut prefix = format!("{}:", row).into_bytes();
        prefix.extend_from_slice(key.as_bytes());
        let h = fnv1a_64(&prefix);
        (h % self.width as u64) as usize
    }

    /// Add n to key's d cells.
    pub fn add(&mut self, key: &str, n: u64) {
        for r in 0..self.depth {
            let c = self.col(r, key);
            let idx = (r as usize) * (self.width as usize) + c;
            self.cells[idx] = self.cells[idx].saturating_add(n);
        }
    }

    /// Estimate key frequency (min across rows).
    pub fn estimate(&self, key: &str) -> u64 {
        let mut best = u64::MAX;
        for r in 0..self.depth {
            let c = self.col(r, key);
            let idx = (r as usize) * (self.width as usize) + c;
            if self.cells[idx] < best {
                best = self.cells[idx];
            }
        }
        best
    }

    /// Reset all cells to zero.
    pub fn reset(&mut self) {
        for c in self.cells.iter_mut() {
            *c = 0;
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CmsError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CmsError::SchemaMismatch);
        }
        if self.depth == 0 || self.width == 0 {
            return Err(CmsError::ZeroDim);
        }
        if self.cells.len() != (self.depth as usize) * (self.width as usize) {
            return Err(CmsError::BadCells);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_then_estimate_exact_for_single_key() {
        let mut s = CountMinSketch::new(4, 64).unwrap();
        s.add("k", 5);
        s.add("k", 3);
        assert_eq!(s.estimate("k"), 8);
    }

    #[test]
    fn unknown_key_is_zero() {
        let s = CountMinSketch::new(4, 64).unwrap();
        assert_eq!(s.estimate("nope"), 0);
    }

    #[test]
    fn estimate_is_upper_bound() {
        let mut s = CountMinSketch::new(4, 128).unwrap();
        for i in 0..1000 {
            s.add(&format!("k{}", i), 1);
        }
        // Any single key contributed exactly 1, so estimate >= 1.
        assert!(s.estimate("k0") >= 1);
    }

    #[test]
    fn reset_zeros_all() {
        let mut s = CountMinSketch::new(2, 16).unwrap();
        s.add("a", 100);
        s.reset();
        assert_eq!(s.estimate("a"), 0);
    }

    #[test]
    fn zero_dim_rejected() {
        assert!(matches!(
            CountMinSketch::new(0, 16).unwrap_err(),
            CmsError::ZeroDim
        ));
        assert!(matches!(
            CountMinSketch::new(4, 0).unwrap_err(),
            CmsError::ZeroDim
        ));
    }

    #[test]
    fn bad_cells_rejected() {
        let mut s = CountMinSketch::new(2, 4).unwrap();
        s.cells.pop();
        assert!(matches!(s.validate().unwrap_err(), CmsError::BadCells));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = CountMinSketch::new(2, 4).unwrap();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            CmsError::SchemaMismatch
        ));
    }

    #[test]
    fn sketch_serde_roundtrip() {
        let mut s = CountMinSketch::new(3, 32).unwrap();
        s.add("a", 7);
        s.add("b", 2);
        let j = serde_json::to_string(&s).unwrap();
        let back: CountMinSketch = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
        assert_eq!(back.estimate("a"), 7);
        assert_eq!(back.estimate("b"), 2);
    }
}
