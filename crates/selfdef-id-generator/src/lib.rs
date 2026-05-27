//! `selfdef-id-generator` — ULID-like time-prefixed IDs.
//!
//! ID layout (128 bits): top 48 bits = ms timestamp; bottom 80
//! bits = per-tick counter that starts at 0 each new ms and
//! increments monotonically while ts_ms is the same. Output as
//! 26-char Crockford base32. Same (now_ms, sequence) yields
//! identical strings — pure deterministic.
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
pub struct IdGenerator {
    /// Schema version.
    pub schema_version: String,
    /// Last seen ts_ms.
    pub last_ts_ms: u64,
    /// Sequence within last_ts_ms.
    pub sequence: u128,
    /// Total ids emitted.
    pub emitted: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum IdError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Clock regression.
    #[error("clock regression: {now} < {last}")]
    ClockRegression {
        /// Submitted now.
        now: u64,
        /// Last ts.
        last: u64,
    },
    /// Sequence overflow within a single ms (>= 2^80).
    #[error("sequence overflow")]
    SequenceOverflow,
}

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn encode_u128_base32_26(mut value: u128) -> String {
    let mut buf = [0u8; 26];
    for slot in buf.iter_mut().rev() {
        *slot = CROCKFORD[(value & 0x1F) as usize];
        value >>= 5;
    }
    String::from_utf8(buf.to_vec()).unwrap()
}

impl IdGenerator {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            last_ts_ms: 0,
            sequence: 0,
            emitted: 0,
        }
    }

    /// Emit next id at now_ms.
    pub fn next(&mut self, now_ms: u64) -> Result<String, IdError> {
        if now_ms < self.last_ts_ms {
            return Err(IdError::ClockRegression {
                now: now_ms,
                last: self.last_ts_ms,
            });
        }
        if now_ms > self.last_ts_ms {
            self.last_ts_ms = now_ms;
            self.sequence = 0;
        } else {
            // Same tick — bump sequence (within 80 bits).
            if self.sequence >= (1u128 << 80) - 1 {
                return Err(IdError::SequenceOverflow);
            }
            self.sequence += 1;
        }
        let value: u128 = ((now_ms as u128) << 80) | self.sequence;
        self.emitted = self.emitted.saturating_add(1);
        Ok(encode_u128_base32_26(value))
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), IdError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(IdError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for IdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_26_chars() {
        let mut g = IdGenerator::new();
        let id = g.next(0).unwrap();
        assert_eq!(id.len(), 26);
    }

    #[test]
    fn deterministic_same_ts() {
        let mut a = IdGenerator::new();
        let mut b = IdGenerator::new();
        let xa = a.next(1234).unwrap();
        let xb = b.next(1234).unwrap();
        assert_eq!(xa, xb);
    }

    #[test]
    fn monotonic_within_same_ts() {
        let mut g = IdGenerator::new();
        let a = g.next(100).unwrap();
        let b = g.next(100).unwrap();
        let c = g.next(100).unwrap();
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn larger_ts_yields_larger_id() {
        let mut g = IdGenerator::new();
        let a = g.next(100).unwrap();
        let b = g.next(200).unwrap();
        assert!(a < b);
    }

    #[test]
    fn clock_regression_rejected() {
        let mut g = IdGenerator::new();
        g.next(100).unwrap();
        assert!(matches!(
            g.next(50).unwrap_err(),
            IdError::ClockRegression { .. }
        ));
    }

    #[test]
    fn sequence_resets_on_new_ms() {
        let mut g = IdGenerator::new();
        g.next(100).unwrap();
        g.next(100).unwrap();
        g.next(101).unwrap();
        assert_eq!(g.sequence, 0);
    }

    #[test]
    fn alphabet_uses_crockford_only() {
        let mut g = IdGenerator::new();
        let id = g.next(12345).unwrap();
        for c in id.chars() {
            assert!(CROCKFORD.contains(&(c as u8)), "bad char: {}", c);
        }
    }

    #[test]
    fn schema_drift_rejected() {
        let mut g = IdGenerator::new();
        g.schema_version = "9.9.9".into();
        assert!(matches!(g.validate().unwrap_err(), IdError::SchemaMismatch));
    }

    #[test]
    fn gen_serde_roundtrip() {
        let mut g = IdGenerator::new();
        g.next(1234).unwrap();
        let j = serde_json::to_string(&g).unwrap();
        let back: IdGenerator = serde_json::from_str(&j).unwrap();
        assert_eq!(g, back);
    }
}
