//! `selfdef-permit-semaphore` — counting permit pool.
//!
//! capacity N permits. try_acquire(n) returns Ok if n permits
//! available (held increases by n; high-water updated), Err
//! Exhausted otherwise (rejected counter increments).
//! release(n) returns held to pool (saturating at 0). Pure
//! data; no async.
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
pub struct PermitSemaphore {
    /// Schema version.
    pub schema_version: String,
    /// Capacity.
    pub capacity: u32,
    /// Currently held.
    pub held: u32,
    /// High-water mark.
    pub high_water: u32,
    /// Acquired count.
    pub acquired: u64,
    /// Rejected count.
    pub rejected: u64,
    /// Released count.
    pub released: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SemaphoreError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero capacity.
    #[error("capacity must be >= 1")]
    ZeroCapacity,
    /// Bad n.
    #[error("n must be >= 1")]
    ZeroN,
    /// Exhausted.
    #[error("exhausted: needed {needed}, available {available}")]
    Exhausted {
        /// Needed.
        needed: u32,
        /// Available.
        available: u32,
    },
}

impl PermitSemaphore {
    /// New.
    pub fn new(capacity: u32) -> Result<Self, SemaphoreError> {
        if capacity == 0 { return Err(SemaphoreError::ZeroCapacity); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            capacity,
            held: 0,
            high_water: 0,
            acquired: 0,
            rejected: 0,
            released: 0,
        })
    }

    /// Available permits.
    pub fn available(&self) -> u32 {
        self.capacity.saturating_sub(self.held)
    }

    /// Try to acquire `n` permits.
    pub fn try_acquire(&mut self, n: u32) -> Result<(), SemaphoreError> {
        if n == 0 { return Err(SemaphoreError::ZeroN); }
        let av = self.available();
        if n > av {
            self.rejected = self.rejected.saturating_add(1);
            return Err(SemaphoreError::Exhausted { needed: n, available: av });
        }
        self.held = self.held.saturating_add(n);
        if self.held > self.high_water { self.high_water = self.held; }
        self.acquired = self.acquired.saturating_add(1);
        Ok(())
    }

    /// Release `n` permits (saturating at 0).
    pub fn release(&mut self, n: u32) -> Result<(), SemaphoreError> {
        if n == 0 { return Err(SemaphoreError::ZeroN); }
        self.held = self.held.saturating_sub(n);
        self.released = self.released.saturating_add(1);
        Ok(())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), SemaphoreError> {
        if self.schema_version != SCHEMA_VERSION { return Err(SemaphoreError::SchemaMismatch); }
        if self.capacity == 0 { return Err(SemaphoreError::ZeroCapacity); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_and_release() {
        let mut s = PermitSemaphore::new(5).unwrap();
        s.try_acquire(2).unwrap();
        assert_eq!(s.held, 2);
        assert_eq!(s.available(), 3);
        s.release(1).unwrap();
        assert_eq!(s.held, 1);
    }

    #[test]
    fn exhaustion_errors() {
        let mut s = PermitSemaphore::new(3).unwrap();
        s.try_acquire(2).unwrap();
        assert!(matches!(s.try_acquire(2).unwrap_err(), SemaphoreError::Exhausted { needed: 2, available: 1 }));
        assert_eq!(s.rejected, 1);
    }

    #[test]
    fn high_water_tracks_max_held() {
        let mut s = PermitSemaphore::new(10).unwrap();
        s.try_acquire(4).unwrap();
        s.try_acquire(3).unwrap();
        s.release(5).unwrap();
        s.try_acquire(2).unwrap();
        assert_eq!(s.high_water, 7);
    }

    #[test]
    fn release_saturates_at_zero() {
        let mut s = PermitSemaphore::new(5).unwrap();
        s.try_acquire(2).unwrap();
        s.release(10).unwrap();
        assert_eq!(s.held, 0);
    }

    #[test]
    fn zero_n_rejected() {
        let mut s = PermitSemaphore::new(5).unwrap();
        assert!(matches!(s.try_acquire(0).unwrap_err(), SemaphoreError::ZeroN));
        assert!(matches!(s.release(0).unwrap_err(), SemaphoreError::ZeroN));
    }

    #[test]
    fn zero_capacity_rejected() {
        assert!(matches!(PermitSemaphore::new(0).unwrap_err(), SemaphoreError::ZeroCapacity));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = PermitSemaphore::new(5).unwrap();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), SemaphoreError::SchemaMismatch));
    }

    #[test]
    fn sem_serde_roundtrip() {
        let mut s = PermitSemaphore::new(5).unwrap();
        s.try_acquire(2).unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: PermitSemaphore = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
