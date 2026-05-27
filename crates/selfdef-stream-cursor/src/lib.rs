//! `selfdef-stream-cursor` — per-consumer stream offsets.
//!
//! Tracks producer high_water_offset (monotonic) + per-consumer
//! committed_offset. commit(consumer, offset) advances only
//! (rollback rejected). lag(consumer) = high_water - committed.
//! reset(consumer, offset) forcibly sets to any value.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamCursor {
    /// Schema version.
    pub schema_version: String,
    /// Producer high-water mark.
    pub high_water: u64,
    /// consumer id → committed offset.
    pub committed: BTreeMap<String, u64>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CursorError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("consumer empty")]
    EmptyConsumer,
    /// Rollback.
    #[error("rollback: {value} < {committed}")]
    Rollback {
        /// Submitted.
        value: u64,
        /// Current committed.
        committed: u64,
    },
    /// High-water regression.
    #[error("high_water regression: {value} < {current}")]
    HighWaterRegression {
        /// Submitted.
        value: u64,
        /// Current.
        current: u64,
    },
}

impl StreamCursor {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            high_water: 0,
            committed: BTreeMap::new(),
        }
    }

    /// Advance high-water (must be monotonic).
    pub fn advance_high_water(&mut self, value: u64) -> Result<(), CursorError> {
        if value < self.high_water {
            return Err(CursorError::HighWaterRegression {
                value,
                current: self.high_water,
            });
        }
        self.high_water = value;
        Ok(())
    }

    /// Commit a consumer offset (must be advance-only).
    pub fn commit(&mut self, consumer: &str, offset: u64) -> Result<(), CursorError> {
        if consumer.is_empty() {
            return Err(CursorError::EmptyConsumer);
        }
        let prev = *self.committed.get(consumer).unwrap_or(&0);
        if offset < prev {
            return Err(CursorError::Rollback {
                value: offset,
                committed: prev,
            });
        }
        self.committed.insert(consumer.into(), offset);
        Ok(())
    }

    /// Reset a consumer offset (any direction).
    pub fn reset(&mut self, consumer: &str, offset: u64) -> Result<(), CursorError> {
        if consumer.is_empty() {
            return Err(CursorError::EmptyConsumer);
        }
        self.committed.insert(consumer.into(), offset);
        Ok(())
    }

    /// Lag for a consumer (high_water - committed; 0 if unknown).
    pub fn lag(&self, consumer: &str) -> u64 {
        let c = *self.committed.get(consumer).unwrap_or(&0);
        self.high_water.saturating_sub(c)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CursorError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CursorError::SchemaMismatch);
        }
        for k in self.committed.keys() {
            if k.is_empty() {
                return Err(CursorError::EmptyConsumer);
            }
        }
        Ok(())
    }
}

impl Default for StreamCursor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lag_zero_when_caught_up() {
        let mut c = StreamCursor::new();
        c.advance_high_water(100).unwrap();
        c.commit("alice", 100).unwrap();
        assert_eq!(c.lag("alice"), 0);
    }

    #[test]
    fn lag_when_behind() {
        let mut c = StreamCursor::new();
        c.advance_high_water(100).unwrap();
        c.commit("alice", 60).unwrap();
        assert_eq!(c.lag("alice"), 40);
    }

    #[test]
    fn unknown_consumer_lag_is_high_water() {
        let mut c = StreamCursor::new();
        c.advance_high_water(50).unwrap();
        assert_eq!(c.lag("nobody"), 50);
    }

    #[test]
    fn commit_advance_only() {
        let mut c = StreamCursor::new();
        c.commit("a", 10).unwrap();
        c.commit("a", 20).unwrap();
        assert!(matches!(
            c.commit("a", 5).unwrap_err(),
            CursorError::Rollback { .. }
        ));
    }

    #[test]
    fn high_water_advance_only() {
        let mut c = StreamCursor::new();
        c.advance_high_water(50).unwrap();
        assert!(matches!(
            c.advance_high_water(40).unwrap_err(),
            CursorError::HighWaterRegression { .. }
        ));
    }

    #[test]
    fn reset_allows_any_direction() {
        let mut c = StreamCursor::new();
        c.commit("a", 100).unwrap();
        c.reset("a", 50).unwrap();
        assert_eq!(c.lag("a"), 0); // high_water still 0
    }

    #[test]
    fn empty_consumer_rejected() {
        let mut c = StreamCursor::new();
        assert!(matches!(
            c.commit("", 10).unwrap_err(),
            CursorError::EmptyConsumer
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = StreamCursor::new();
        c.schema_version = "9.9.9".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            CursorError::SchemaMismatch
        ));
    }

    #[test]
    fn cursor_serde_roundtrip() {
        let mut c = StreamCursor::new();
        c.advance_high_water(100).unwrap();
        c.commit("a", 50).unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: StreamCursor = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
