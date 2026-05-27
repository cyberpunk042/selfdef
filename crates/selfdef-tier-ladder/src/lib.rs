//! `selfdef-tier-ladder` — promote / demote between ordered tiers.
//!
//! tiers: a non-empty ordered list of tier names. current is the
//! index. promote moves toward end; demote moves toward 0. Both
//! are bounded; at boundary, returns AtEnd. Transitions append
//! to history (capacity-bounded ring).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Direction.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    /// Promote.
    Promote,
    /// Demote.
    Demote,
}

/// History record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transition {
    /// From tier name.
    pub from: String,
    /// To tier name.
    pub to: String,
    /// Direction.
    pub direction: Direction,
    /// ts ms.
    pub ts_ms: u64,
    /// Reason free-form.
    pub reason: String,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TierLadder {
    /// Schema version.
    pub schema_version: String,
    /// Ordered tier names.
    pub tiers: Vec<String>,
    /// Current index.
    pub current: usize,
    /// Transition history (bounded).
    pub history: Vec<Transition>,
    /// History capacity.
    pub history_capacity: u32,
}

/// Errors.
#[derive(Debug, Error)]
pub enum LadderError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty tiers.
    #[error("tiers must be non-empty")]
    NoTiers,
    /// Bad name.
    #[error("tier name empty")]
    EmptyTier,
    /// Bad initial.
    #[error("initial index out of range")]
    BadInitial,
    /// At end.
    #[error("at boundary")]
    AtBoundary,
    /// Empty reason.
    #[error("reason empty")]
    EmptyReason,
    /// Bad cap.
    #[error("history capacity must be >= 1")]
    ZeroCapacity,
}

impl TierLadder {
    /// New.
    pub fn new(
        tiers: Vec<String>,
        initial_index: usize,
        history_capacity: u32,
    ) -> Result<Self, LadderError> {
        if tiers.is_empty() {
            return Err(LadderError::NoTiers);
        }
        for t in &tiers {
            if t.is_empty() {
                return Err(LadderError::EmptyTier);
            }
        }
        if initial_index >= tiers.len() {
            return Err(LadderError::BadInitial);
        }
        if history_capacity == 0 {
            return Err(LadderError::ZeroCapacity);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            tiers,
            current: initial_index,
            history: Vec::new(),
            history_capacity,
        })
    }

    /// Current tier name.
    pub fn current_tier(&self) -> &str {
        &self.tiers[self.current]
    }

    /// Promote.
    pub fn promote(&mut self, reason: &str, ts_ms: u64) -> Result<&str, LadderError> {
        self.step(Direction::Promote, reason, ts_ms)
    }

    /// Demote.
    pub fn demote(&mut self, reason: &str, ts_ms: u64) -> Result<&str, LadderError> {
        self.step(Direction::Demote, reason, ts_ms)
    }

    fn step(&mut self, dir: Direction, reason: &str, ts_ms: u64) -> Result<&str, LadderError> {
        if reason.is_empty() {
            return Err(LadderError::EmptyReason);
        }
        let new = match dir {
            Direction::Promote => {
                if self.current + 1 >= self.tiers.len() {
                    return Err(LadderError::AtBoundary);
                }
                self.current + 1
            }
            Direction::Demote => {
                if self.current == 0 {
                    return Err(LadderError::AtBoundary);
                }
                self.current - 1
            }
        };
        let from = self.tiers[self.current].clone();
        let to = self.tiers[new].clone();
        self.current = new;
        let rec = Transition {
            from,
            to,
            direction: dir,
            ts_ms,
            reason: reason.into(),
        };
        if (self.history.len() as u32) >= self.history_capacity {
            self.history.remove(0);
        }
        self.history.push(rec);
        Ok(&self.tiers[self.current])
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), LadderError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(LadderError::SchemaMismatch);
        }
        if self.tiers.is_empty() {
            return Err(LadderError::NoTiers);
        }
        if self.current >= self.tiers.len() {
            return Err(LadderError::BadInitial);
        }
        for t in &self.tiers {
            if t.is_empty() {
                return Err(LadderError::EmptyTier);
            }
        }
        if self.history_capacity == 0 {
            return Err(LadderError::ZeroCapacity);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ladder() -> TierLadder {
        TierLadder::new(vec!["bronze".into(), "silver".into(), "gold".into()], 0, 5).unwrap()
    }

    #[test]
    fn promote_climbs() {
        let mut l = ladder();
        assert_eq!(l.promote("good", 100).unwrap(), "silver");
        assert_eq!(l.promote("better", 200).unwrap(), "gold");
        assert_eq!(l.history.len(), 2);
    }

    #[test]
    fn demote_descends() {
        let mut l = ladder();
        l.promote("p", 100).unwrap();
        assert_eq!(l.demote("d", 200).unwrap(), "bronze");
    }

    #[test]
    fn promote_at_top_rejected() {
        let mut l = ladder();
        l.promote("p", 0).unwrap();
        l.promote("p", 0).unwrap();
        assert!(matches!(
            l.promote("p", 0).unwrap_err(),
            LadderError::AtBoundary
        ));
    }

    #[test]
    fn demote_at_bottom_rejected() {
        let mut l = ladder();
        assert!(matches!(
            l.demote("d", 0).unwrap_err(),
            LadderError::AtBoundary
        ));
    }

    #[test]
    fn history_capped() {
        let mut l = TierLadder::new(vec!["a".into(), "b".into(), "c".into()], 0, 2).unwrap();
        l.promote("p1", 1).unwrap();
        l.promote("p2", 2).unwrap();
        l.demote("d1", 3).unwrap();
        assert_eq!(l.history.len(), 2);
        assert_eq!(l.history[0].reason, "p2");
        assert_eq!(l.history[1].reason, "d1");
    }

    #[test]
    fn empty_reason_rejected() {
        let mut l = ladder();
        assert!(matches!(
            l.promote("", 0).unwrap_err(),
            LadderError::EmptyReason
        ));
    }

    #[test]
    fn bad_init_rejected() {
        let r = TierLadder::new(vec!["a".into()], 5, 1);
        assert!(matches!(r.unwrap_err(), LadderError::BadInitial));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut l = ladder();
        l.schema_version = "9.9.9".into();
        assert!(matches!(
            l.validate().unwrap_err(),
            LadderError::SchemaMismatch
        ));
    }

    #[test]
    fn ladder_serde_roundtrip() {
        let mut l = ladder();
        l.promote("p", 100).unwrap();
        let j = serde_json::to_string(&l).unwrap();
        let back: TierLadder = serde_json::from_str(&j).unwrap();
        assert_eq!(l, back);
    }
}
