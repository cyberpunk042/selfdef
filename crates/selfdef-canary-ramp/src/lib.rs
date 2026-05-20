//! `selfdef-canary-ramp` — percent-rollout schedule.
//!
//! Schedule: ordered (ts_ms, percent_bp) points (strictly
//! increasing ts; percent_bp 0..=10000). current_percent(now)
//! returns the latest applicable percent. admit(now, key)
//! hashes (key, seed) via FNV-1a-64, compares mod 10000 to
//! current percent.
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
    /// ts ms.
    pub ts_ms: u64,
    /// percent in bp 0..=10000.
    pub percent_bp: u32,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanaryRamp {
    /// Schema version.
    pub schema_version: String,
    /// Strictly increasing-by-ts points.
    pub points: Vec<Point>,
    /// Seed (must be != 0).
    pub seed: u64,
    /// Admits counted.
    pub admits: u64,
    /// Denials counted.
    pub denials: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RampError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero seed.
    #[error("seed must be != 0")]
    ZeroSeed,
    /// Bad point.
    #[error("percent_bp must be <= 10000")]
    BadPercent,
    /// Bad order.
    #[error("points must be strictly increasing by ts_ms")]
    NotStrictlyIncreasing,
    /// Empty.
    #[error("key empty")]
    EmptyKey,
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

impl CanaryRamp {
    /// New.
    pub fn new(points: Vec<Point>, seed: u64) -> Result<Self, RampError> {
        if seed == 0 { return Err(RampError::ZeroSeed); }
        for p in &points {
            if p.percent_bp > 10_000 { return Err(RampError::BadPercent); }
        }
        for w in points.windows(2) {
            if w[0].ts_ms >= w[1].ts_ms { return Err(RampError::NotStrictlyIncreasing); }
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            points,
            seed,
            admits: 0,
            denials: 0,
        })
    }

    /// Current percent (last point with ts_ms <= now; 0 if no points or all in future).
    pub fn current_percent(&self, now_ms: u64) -> u32 {
        let mut cur = 0u32;
        for p in &self.points {
            if p.ts_ms <= now_ms { cur = p.percent_bp; } else { break; }
        }
        cur
    }

    /// Admit decision (true/false).
    pub fn admit(&mut self, now_ms: u64, key: &str) -> Result<bool, RampError> {
        if key.is_empty() { return Err(RampError::EmptyKey); }
        let pct = self.current_percent(now_ms);
        let mut buf = Vec::with_capacity(key.len() + 8);
        buf.extend_from_slice(key.as_bytes());
        buf.extend_from_slice(&self.seed.to_be_bytes());
        let h = fnv1a_64(&buf);
        let bucket = (h % 10_000) as u32;
        let admit = bucket < pct;
        if admit { self.admits = self.admits.saturating_add(1); }
        else { self.denials = self.denials.saturating_add(1); }
        Ok(admit)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RampError> {
        if self.schema_version != SCHEMA_VERSION { return Err(RampError::SchemaMismatch); }
        if self.seed == 0 { return Err(RampError::ZeroSeed); }
        for p in &self.points {
            if p.percent_bp > 10_000 { return Err(RampError::BadPercent); }
        }
        for w in self.points.windows(2) {
            if w[0].ts_ms >= w[1].ts_ms { return Err(RampError::NotStrictlyIncreasing); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ramp() -> CanaryRamp {
        CanaryRamp::new(
            vec![
                Point { ts_ms: 0, percent_bp: 0 },
                Point { ts_ms: 1000, percent_bp: 5000 },
                Point { ts_ms: 2000, percent_bp: 10000 },
            ],
            42,
        ).unwrap()
    }

    #[test]
    fn percent_progresses() {
        let r = ramp();
        assert_eq!(r.current_percent(0), 0);
        assert_eq!(r.current_percent(500), 0);
        assert_eq!(r.current_percent(1000), 5000);
        assert_eq!(r.current_percent(1500), 5000);
        assert_eq!(r.current_percent(2000), 10000);
        assert_eq!(r.current_percent(99999), 10000);
    }

    #[test]
    fn percent_0_denies_all() {
        let mut r = ramp();
        let mut admitted = 0;
        for k in 0..200 {
            if r.admit(0, &k.to_string()).unwrap() { admitted += 1; }
        }
        assert_eq!(admitted, 0);
    }

    #[test]
    fn percent_100_admits_all() {
        let mut r = ramp();
        let mut admitted = 0;
        for k in 0..200 {
            if r.admit(2000, &k.to_string()).unwrap() { admitted += 1; }
        }
        assert_eq!(admitted, 200);
    }

    #[test]
    fn percent_50_admits_about_half() {
        let mut r = ramp();
        let mut admitted = 0;
        for k in 0..2000 {
            if r.admit(1000, &k.to_string()).unwrap() { admitted += 1; }
        }
        // Expect ~1000 ± 15%.
        assert!((800..=1200).contains(&admitted), "got {}", admitted);
    }

    #[test]
    fn deterministic_same_inputs() {
        let mut a = ramp();
        let mut b = ramp();
        for k in 0..50 {
            assert_eq!(a.admit(1000, &k.to_string()).unwrap(), b.admit(1000, &k.to_string()).unwrap());
        }
    }

    #[test]
    fn bad_inputs_rejected() {
        assert!(matches!(
            CanaryRamp::new(vec![Point { ts_ms: 0, percent_bp: 10001 }], 1).unwrap_err(),
            RampError::BadPercent
        ));
        assert!(matches!(
            CanaryRamp::new(vec![Point { ts_ms: 1, percent_bp: 0 }, Point { ts_ms: 1, percent_bp: 0 }], 1).unwrap_err(),
            RampError::NotStrictlyIncreasing
        ));
        assert!(matches!(CanaryRamp::new(vec![], 0).unwrap_err(), RampError::ZeroSeed));
        let mut r = ramp();
        assert!(matches!(r.admit(0, "").unwrap_err(), RampError::EmptyKey));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = ramp();
        r.schema_version = "9.9.9".into();
        assert!(matches!(r.validate().unwrap_err(), RampError::SchemaMismatch));
    }

    #[test]
    fn ramp_serde_roundtrip() {
        let mut r = ramp();
        r.admit(1000, "a").unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: CanaryRamp = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
