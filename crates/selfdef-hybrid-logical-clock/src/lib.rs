//! `selfdef-hybrid-logical-clock` — Kulkarni-style HLC.
//!
//! Timestamp{wall_ms, counter}. now(wall_now) advances local clock
//! per HLC rules:
//!   new_wall = max(prev_wall, wall_now)
//!   new_counter = if new_wall == prev_wall then prev_counter + 1 else 0
//! update(remote, wall_now) merges a remote timestamp:
//!   new_wall = max(prev_wall, remote.wall_ms, wall_now)
//!   if new_wall == prev_wall == remote.wall: counter = max(prev_counter, remote.counter) + 1
//!   else if new_wall == prev_wall: counter = prev_counter + 1
//!   else if new_wall == remote.wall: counter = remote.counter + 1
//!   else: counter = 0
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Timestamp.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Timestamp {
    /// Wall ms.
    pub wall_ms: u64,
    /// Logical counter.
    pub counter: u32,
}

impl PartialOrd for Timestamp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Timestamp {
    fn cmp(&self, other: &Self) -> Ordering {
        self.wall_ms
            .cmp(&other.wall_ms)
            .then(self.counter.cmp(&other.counter))
    }
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HybridLogicalClock {
    /// Schema version.
    pub schema_version: String,
    /// Current state.
    pub current: Timestamp,
}

/// Errors.
#[derive(Debug, Error)]
pub enum HlcError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Overflow.
    #[error("counter overflowed")]
    Overflow,
}

impl HybridLogicalClock {
    /// New (initial wall=0, counter=0).
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            current: Timestamp {
                wall_ms: 0,
                counter: 0,
            },
        }
    }

    /// Local tick.
    pub fn now(&mut self, wall_now: u64) -> Result<Timestamp, HlcError> {
        let prev = self.current;
        let new_wall = prev.wall_ms.max(wall_now);
        let new_counter = if new_wall == prev.wall_ms {
            prev.counter.checked_add(1).ok_or(HlcError::Overflow)?
        } else {
            0
        };
        self.current = Timestamp {
            wall_ms: new_wall,
            counter: new_counter,
        };
        Ok(self.current)
    }

    /// Merge with remote.
    pub fn update(&mut self, remote: Timestamp, wall_now: u64) -> Result<Timestamp, HlcError> {
        let prev = self.current;
        let new_wall = prev.wall_ms.max(remote.wall_ms).max(wall_now);
        let new_counter = if new_wall == prev.wall_ms && new_wall == remote.wall_ms {
            prev.counter
                .max(remote.counter)
                .checked_add(1)
                .ok_or(HlcError::Overflow)?
        } else if new_wall == prev.wall_ms {
            prev.counter.checked_add(1).ok_or(HlcError::Overflow)?
        } else if new_wall == remote.wall_ms {
            remote.counter.checked_add(1).ok_or(HlcError::Overflow)?
        } else {
            0
        };
        self.current = Timestamp {
            wall_ms: new_wall,
            counter: new_counter,
        };
        Ok(self.current)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), HlcError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(HlcError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for HybridLogicalClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_advances_monotonically() {
        let mut h = HybridLogicalClock::new();
        let a = h.now(100).unwrap();
        let b = h.now(100).unwrap();
        let c = h.now(200).unwrap();
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn same_wall_increments_counter() {
        let mut h = HybridLogicalClock::new();
        h.now(100).unwrap();
        let t = h.now(100).unwrap();
        assert_eq!(t.wall_ms, 100);
        assert!(t.counter >= 1);
    }

    #[test]
    fn wall_jump_resets_counter() {
        let mut h = HybridLogicalClock::new();
        h.now(100).unwrap();
        h.now(100).unwrap();
        let t = h.now(500).unwrap();
        assert_eq!(t.wall_ms, 500);
        assert_eq!(t.counter, 0);
    }

    #[test]
    fn update_with_remote_ahead() {
        let mut h = HybridLogicalClock::new();
        h.now(100).unwrap();
        let remote = Timestamp {
            wall_ms: 1000,
            counter: 5,
        };
        let t = h.update(remote, 100).unwrap();
        assert_eq!(t.wall_ms, 1000);
        assert_eq!(t.counter, 6);
    }

    #[test]
    fn update_same_wall_max_counter() {
        let mut h = HybridLogicalClock::new();
        h.now(100).unwrap();
        h.now(100).unwrap();
        // Local counter is 1. Remote at same wall, counter 3 → max+1 = 4.
        let remote = Timestamp {
            wall_ms: 100,
            counter: 3,
        };
        let t = h.update(remote, 100).unwrap();
        assert_eq!(t.wall_ms, 100);
        assert_eq!(t.counter, 4);
    }

    #[test]
    fn cmp_orders_by_wall_then_counter() {
        let a = Timestamp {
            wall_ms: 100,
            counter: 5,
        };
        let b = Timestamp {
            wall_ms: 100,
            counter: 6,
        };
        let c = Timestamp {
            wall_ms: 200,
            counter: 0,
        };
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut h = HybridLogicalClock::new();
        h.schema_version = "9.9.9".into();
        assert!(matches!(
            h.validate().unwrap_err(),
            HlcError::SchemaMismatch
        ));
    }

    #[test]
    fn hlc_serde_roundtrip() {
        let mut h = HybridLogicalClock::new();
        h.now(100).unwrap();
        let j = serde_json::to_string(&h).unwrap();
        let back: HybridLogicalClock = serde_json::from_str(&j).unwrap();
        assert_eq!(h, back);
    }
}
