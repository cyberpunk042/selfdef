//! `selfdef-seat-pool` — fixed-capacity reservation pool.
//!
//! Capacity N seats. acquire(holder_id, ts) reserves a seat if
//! available (errors AtCapacity otherwise; also DuplicateHolder
//! if the holder already holds). release(holder_id) frees one.
//! expire(now, ttl_ms) sweeps holders whose ts is older than
//! ttl, releasing them.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Holder record.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Holder {
    /// Acquired ts ms.
    pub acquired_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeatPool {
    /// Schema version.
    pub schema_version: String,
    /// Capacity.
    pub capacity: u32,
    /// holder_id → Holder.
    pub holders: BTreeMap<String, Holder>,
    /// Lifetime acquire count.
    pub acquires: u64,
    /// Lifetime release count.
    pub releases: u64,
    /// Lifetime expire count.
    pub expires: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SeatError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("holder id empty")]
    EmptyHolder,
    /// Zero capacity.
    #[error("capacity must be >= 1")]
    ZeroCapacity,
    /// Full.
    #[error("at capacity: {0}")]
    AtCapacity(u32),
    /// Duplicate.
    #[error("duplicate holder: {0}")]
    DuplicateHolder(String),
    /// Unknown.
    #[error("unknown holder: {0}")]
    UnknownHolder(String),
}

impl SeatPool {
    /// New.
    pub fn new(capacity: u32) -> Result<Self, SeatError> {
        if capacity == 0 {
            return Err(SeatError::ZeroCapacity);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            capacity,
            holders: BTreeMap::new(),
            acquires: 0,
            releases: 0,
            expires: 0,
        })
    }

    /// Acquire a seat.
    pub fn acquire(&mut self, holder: &str, ts_ms: u64) -> Result<(), SeatError> {
        if holder.is_empty() {
            return Err(SeatError::EmptyHolder);
        }
        if self.holders.contains_key(holder) {
            return Err(SeatError::DuplicateHolder(holder.into()));
        }
        if (self.holders.len() as u32) >= self.capacity {
            return Err(SeatError::AtCapacity(self.capacity));
        }
        self.holders
            .insert(holder.into(), Holder { acquired_ms: ts_ms });
        self.acquires = self.acquires.saturating_add(1);
        Ok(())
    }

    /// Release a seat.
    pub fn release(&mut self, holder: &str) -> Result<(), SeatError> {
        if self.holders.remove(holder).is_none() {
            return Err(SeatError::UnknownHolder(holder.into()));
        }
        self.releases = self.releases.saturating_add(1);
        Ok(())
    }

    /// Expire stale holders (acquired_ms older than now - ttl_ms).
    pub fn expire(&mut self, now_ms: u64, ttl_ms: u64) -> u32 {
        let cutoff = now_ms.saturating_sub(ttl_ms);
        let stale: Vec<String> = self
            .holders
            .iter()
            .filter(|(_, h)| h.acquired_ms < cutoff)
            .map(|(k, _)| k.clone())
            .collect();
        let n = stale.len() as u32;
        for k in stale {
            self.holders.remove(&k);
        }
        self.expires = self.expires.saturating_add(n as u64);
        n
    }

    /// Used count.
    pub fn used(&self) -> u32 {
        self.holders.len() as u32
    }

    /// Available count.
    pub fn available(&self) -> u32 {
        self.capacity.saturating_sub(self.used())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), SeatError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SeatError::SchemaMismatch);
        }
        if self.capacity == 0 {
            return Err(SeatError::ZeroCapacity);
        }
        if (self.holders.len() as u32) > self.capacity {
            return Err(SeatError::AtCapacity(self.capacity));
        }
        for k in self.holders.keys() {
            if k.is_empty() {
                return Err(SeatError::EmptyHolder);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_until_full() {
        let mut p = SeatPool::new(2).unwrap();
        p.acquire("a", 0).unwrap();
        p.acquire("b", 0).unwrap();
        assert!(matches!(
            p.acquire("c", 0).unwrap_err(),
            SeatError::AtCapacity(2)
        ));
    }

    #[test]
    fn release_frees_seat() {
        let mut p = SeatPool::new(2).unwrap();
        p.acquire("a", 0).unwrap();
        p.acquire("b", 0).unwrap();
        p.release("a").unwrap();
        p.acquire("c", 0).unwrap();
        assert_eq!(p.used(), 2);
    }

    #[test]
    fn duplicate_holder_rejected() {
        let mut p = SeatPool::new(2).unwrap();
        p.acquire("a", 0).unwrap();
        assert!(matches!(
            p.acquire("a", 0).unwrap_err(),
            SeatError::DuplicateHolder(_)
        ));
    }

    #[test]
    fn unknown_release_rejected() {
        let mut p = SeatPool::new(2).unwrap();
        assert!(matches!(
            p.release("nope").unwrap_err(),
            SeatError::UnknownHolder(_)
        ));
    }

    #[test]
    fn expire_sweeps_stale() {
        let mut p = SeatPool::new(3).unwrap();
        p.acquire("a", 100).unwrap();
        p.acquire("b", 500).unwrap();
        p.acquire("c", 900).unwrap();
        let n = p.expire(1000, 600);
        // cutoff = 1000-600 = 400; a (100) < 400, b/c >= 400.
        assert_eq!(n, 1);
        assert_eq!(p.used(), 2);
        assert_eq!(p.expires, 1);
    }

    #[test]
    fn available_correct() {
        let mut p = SeatPool::new(5).unwrap();
        p.acquire("a", 0).unwrap();
        p.acquire("b", 0).unwrap();
        assert_eq!(p.available(), 3);
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut p = SeatPool::new(2).unwrap();
        assert!(matches!(
            p.acquire("", 0).unwrap_err(),
            SeatError::EmptyHolder
        ));
        assert!(matches!(
            SeatPool::new(0).unwrap_err(),
            SeatError::ZeroCapacity
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = SeatPool::new(2).unwrap();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            SeatError::SchemaMismatch
        ));
    }

    #[test]
    fn pool_serde_roundtrip() {
        let mut p = SeatPool::new(2).unwrap();
        p.acquire("a", 0).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: SeatPool = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
