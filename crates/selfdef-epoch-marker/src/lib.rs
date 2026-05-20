//! `selfdef-epoch-marker` — monotonic global epoch + tagging.
//!
//! advance() bumps the current epoch by 1 (used at coarse phase
//! changes — restart, snapshot rotation, config reload). tag(now)
//! returns the (epoch, seq) for an event, where seq monotonically
//! increases within an epoch and resets to 0 on advance. Compare
//! (e1, s1) < (e2, s2) lexicographically.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Tag (epoch, seq).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tag {
    /// Epoch.
    pub epoch: u64,
    /// Sequence within epoch.
    pub seq: u64,
}

impl PartialOrd for Tag {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Tag {
    fn cmp(&self, other: &Self) -> Ordering {
        self.epoch.cmp(&other.epoch).then(self.seq.cmp(&other.seq))
    }
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpochMarker {
    /// Schema version.
    pub schema_version: String,
    /// Current epoch.
    pub epoch: u64,
    /// Next seq within current epoch.
    pub next_seq: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum EpochError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Exhausted.
    #[error("epoch or seq exhausted")]
    Exhausted,
}

impl EpochMarker {
    /// New (epoch 0, seq 0).
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            epoch: 0,
            next_seq: 0,
        }
    }

    /// Advance to next epoch; resets seq to 0.
    pub fn advance(&mut self) -> Result<(), EpochError> {
        self.epoch = self.epoch.checked_add(1).ok_or(EpochError::Exhausted)?;
        self.next_seq = 0;
        Ok(())
    }

    /// Tag the next event.
    pub fn tag(&mut self) -> Result<Tag, EpochError> {
        let t = Tag { epoch: self.epoch, seq: self.next_seq };
        self.next_seq = self.next_seq.checked_add(1).ok_or(EpochError::Exhausted)?;
        Ok(t)
    }

    /// Peek next tag without consuming.
    pub fn peek(&self) -> Tag {
        Tag { epoch: self.epoch, seq: self.next_seq }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), EpochError> {
        if self.schema_version != SCHEMA_VERSION { return Err(EpochError::SchemaMismatch); }
        Ok(())
    }
}

impl Default for EpochMarker {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_increments_seq() {
        let mut m = EpochMarker::new();
        assert_eq!(m.tag().unwrap(), Tag { epoch: 0, seq: 0 });
        assert_eq!(m.tag().unwrap(), Tag { epoch: 0, seq: 1 });
        assert_eq!(m.tag().unwrap(), Tag { epoch: 0, seq: 2 });
    }

    #[test]
    fn advance_resets_seq_and_bumps_epoch() {
        let mut m = EpochMarker::new();
        m.tag().unwrap();
        m.tag().unwrap();
        m.advance().unwrap();
        assert_eq!(m.tag().unwrap(), Tag { epoch: 1, seq: 0 });
    }

    #[test]
    fn tag_order_is_lex() {
        let a = Tag { epoch: 1, seq: 5 };
        let b = Tag { epoch: 1, seq: 6 };
        let c = Tag { epoch: 2, seq: 0 };
        assert!(a < b);
        assert!(b < c);
        assert!(a < c);
    }

    #[test]
    fn peek_does_not_consume() {
        let mut m = EpochMarker::new();
        let p1 = m.peek();
        let p2 = m.peek();
        assert_eq!(p1, p2);
        let t = m.tag().unwrap();
        assert_eq!(t, p1);
    }

    #[test]
    fn epoch_exhausted() {
        let mut m = EpochMarker::new();
        m.epoch = u64::MAX;
        assert!(matches!(m.advance().unwrap_err(), EpochError::Exhausted));
    }

    #[test]
    fn seq_exhausted() {
        let mut m = EpochMarker::new();
        m.next_seq = u64::MAX - 1;
        m.tag().unwrap();
        // next_seq is now u64::MAX; another tag overflows on increment.
        assert!(matches!(m.tag().unwrap_err(), EpochError::Exhausted));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut m = EpochMarker::new();
        m.schema_version = "9.9.9".into();
        assert!(matches!(m.validate().unwrap_err(), EpochError::SchemaMismatch));
    }

    #[test]
    fn marker_serde_roundtrip() {
        let mut m = EpochMarker::new();
        m.tag().unwrap();
        m.advance().unwrap();
        m.tag().unwrap();
        let j = serde_json::to_string(&m).unwrap();
        let back: EpochMarker = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
    }
}
