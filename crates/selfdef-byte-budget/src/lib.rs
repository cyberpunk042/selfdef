//! `selfdef-byte-budget` — bounded byte budget with watermarks.
//!
//! capacity is total bytes. reserve(n) succeeds iff n+in_use <=
//! capacity, then adds n to in_use AND updates high_watermark.
//! release(n) saturating-subtracts. available() returns
//! capacity - in_use.
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
pub struct ByteBudget {
    /// Schema version.
    pub schema_version: String,
    /// Capacity bytes.
    pub capacity: u64,
    /// In use.
    pub in_use: u64,
    /// High watermark.
    pub high_watermark: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BudgetError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero capacity.
    #[error("capacity must be >= 1")]
    ZeroCapacity,
    /// Exceeded.
    #[error("would exceed capacity: requested {requested}, available {available}")]
    Exceeded {
        /// Requested.
        requested: u64,
        /// Available.
        available: u64,
    },
}

impl ByteBudget {
    /// New.
    pub fn new(capacity: u64) -> Result<Self, BudgetError> {
        if capacity == 0 {
            return Err(BudgetError::ZeroCapacity);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            capacity,
            in_use: 0,
            high_watermark: 0,
        })
    }

    /// Reserve n bytes.
    pub fn reserve(&mut self, n: u64) -> Result<(), BudgetError> {
        // saturating: reserve() keeps in_use <= capacity, but a serde-bypassed
        // state can violate it. A plain `capacity - in_use` would then underflow
        // — a debug panic and, in release, a wrap to a huge bogus `avail` so the
        // `n > avail` check passes and an OVER-budget reservation is allowed
        // (fail-OPEN). Saturate to 0: an over-budget budget grants nothing.
        let avail = self.capacity.saturating_sub(self.in_use);
        if n > avail {
            return Err(BudgetError::Exceeded {
                requested: n,
                available: avail,
            });
        }
        self.in_use = self.in_use.saturating_add(n);
        if self.in_use > self.high_watermark {
            self.high_watermark = self.in_use;
        }
        Ok(())
    }

    /// Release n bytes.
    pub fn release(&mut self, n: u64) {
        self.in_use = self.in_use.saturating_sub(n);
    }

    /// Bytes available.
    pub fn available(&self) -> u64 {
        // saturating: a serde-bypassed in_use > capacity (charge() keeps the
        // invariant, but deserialization can violate it) would otherwise
        // underflow — a debug panic and, in release, a wrap to a huge bogus
        // "available" (fail-OPEN). Saturate to 0: an over-budget state has
        // nothing available (fail-CLOSED).
        self.capacity.saturating_sub(self.in_use)
    }

    /// Fraction in use, in basis points.
    pub fn used_bp(&self) -> u32 {
        // new()/validate() reject capacity==0, but serde can set it directly;
        // the division would then panic in every build (integer div-by-zero is
        // never masked). A zero-capacity budget has no room — report fully
        // used (fail-CLOSED) rather than crash.
        if self.capacity == 0 {
            return 10_000;
        }
        ((self.in_use as u128 * 10_000) / self.capacity as u128) as u32
    }

    /// Reset high watermark to current in_use.
    pub fn reset_watermark(&mut self) {
        self.high_watermark = self.in_use;
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BudgetError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BudgetError::SchemaMismatch);
        }
        if self.capacity == 0 {
            return Err(BudgetError::ZeroCapacity);
        }
        if self.in_use > self.capacity {
            return Err(BudgetError::Exceeded {
                requested: self.in_use,
                available: self.capacity,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_capacity_and_overuse_serde_bypass_do_not_panic() {
        // new()/validate() reject capacity==0 and keep in_use<=capacity, but
        // serde can violate both. used_bp()'s `/ self.capacity` would panic and
        // available()'s `capacity - in_use` would underflow. Guards make them
        // fail-closed (0 available, 100% used) instead of crashing/wrapping.
        let b = ByteBudget {
            schema_version: SCHEMA_VERSION.into(),
            capacity: 0,
            in_use: 100,
            high_watermark: 100,
        };
        assert_eq!(b.available(), 0); // saturating, no underflow
        assert_eq!(b.used_bp(), 10_000); // no div-by-zero
    }

    #[test]
    fn over_budget_serde_bypass_reserve_fails_closed() {
        // A serde-bypassed in_use > capacity must not let reserve() underflow
        // `capacity - in_use` (debug panic / release wrap to a huge avail that
        // would WRONGLY admit an over-budget reservation). saturating_sub makes
        // avail 0 → any positive reservation is refused (fail-closed).
        let mut b = ByteBudget {
            schema_version: SCHEMA_VERSION.into(),
            capacity: 100,
            in_use: 500, // over budget
            high_watermark: 500,
        };
        let e = b.reserve(1).unwrap_err(); // must not panic, must refuse
        assert!(matches!(
            e,
            BudgetError::Exceeded {
                requested: 1,
                available: 0
            }
        ));
        assert_eq!(b.in_use, 500); // unchanged — nothing granted
    }

    #[test]
    fn reserve_and_release() {
        let mut b = ByteBudget::new(1000).unwrap();
        b.reserve(300).unwrap();
        assert_eq!(b.in_use, 300);
        assert_eq!(b.available(), 700);
        b.release(100);
        assert_eq!(b.in_use, 200);
    }

    #[test]
    fn high_watermark_tracks_peak() {
        let mut b = ByteBudget::new(1000).unwrap();
        b.reserve(500).unwrap();
        b.reserve(200).unwrap(); // peak 700
        b.release(400);
        assert_eq!(b.high_watermark, 700);
    }

    #[test]
    fn exceeded_rejected() {
        let mut b = ByteBudget::new(100).unwrap();
        b.reserve(80).unwrap();
        let e = b.reserve(30).unwrap_err();
        assert!(matches!(
            e,
            BudgetError::Exceeded {
                requested: 30,
                available: 20
            }
        ));
        // State unchanged.
        assert_eq!(b.in_use, 80);
    }

    #[test]
    fn release_saturates_at_zero() {
        let mut b = ByteBudget::new(1000).unwrap();
        b.reserve(100).unwrap();
        b.release(9999); // saturates
        assert_eq!(b.in_use, 0);
    }

    #[test]
    fn used_bp_at_quarter() {
        let mut b = ByteBudget::new(1000).unwrap();
        b.reserve(250).unwrap();
        assert_eq!(b.used_bp(), 2500);
    }

    #[test]
    fn reset_watermark_to_current() {
        let mut b = ByteBudget::new(1000).unwrap();
        b.reserve(500).unwrap();
        b.release(300);
        b.reset_watermark();
        assert_eq!(b.high_watermark, 200);
    }

    #[test]
    fn zero_capacity_rejected() {
        assert!(matches!(
            ByteBudget::new(0).unwrap_err(),
            BudgetError::ZeroCapacity
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut b = ByteBudget::new(100).unwrap();
        b.schema_version = "9.9.9".into();
        assert!(matches!(
            b.validate().unwrap_err(),
            BudgetError::SchemaMismatch
        ));
    }

    #[test]
    fn budget_serde_roundtrip() {
        let mut b = ByteBudget::new(1000).unwrap();
        b.reserve(200).unwrap();
        let j = serde_json::to_string(&b).unwrap();
        let back: ByteBudget = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
