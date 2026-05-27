//! `selfdef-hysteresis-band` — jitter-suppressed binary state.
//!
//! State{Low/High}. Transition Low→High only when sample >= upper;
//! High→Low only when sample <= lower. Samples in the band leave
//! state unchanged. lower must be < upper. observe(value) returns
//! the new state.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    /// Low.
    Low,
    /// High.
    High,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HysteresisBand {
    /// Schema version.
    pub schema_version: String,
    /// Lower threshold (High → Low when sample <= lower).
    pub lower: i64,
    /// Upper threshold (Low → High when sample >= upper).
    pub upper: i64,
    /// Current state.
    pub state: State,
    /// Total transitions observed.
    pub transitions: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BandError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Bad thresholds.
    #[error("lower must be < upper")]
    BadThresholds,
}

impl HysteresisBand {
    /// New.
    pub fn new(lower: i64, upper: i64, initial: State) -> Result<Self, BandError> {
        if lower >= upper {
            return Err(BandError::BadThresholds);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            lower,
            upper,
            state: initial,
            transitions: 0,
        })
    }

    /// Observe sample; return new state.
    pub fn observe(&mut self, sample: i64) -> State {
        match self.state {
            State::Low if sample >= self.upper => {
                self.state = State::High;
                self.transitions = self.transitions.saturating_add(1);
            }
            State::High if sample <= self.lower => {
                self.state = State::Low;
                self.transitions = self.transitions.saturating_add(1);
            }
            _ => {}
        }
        self.state
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BandError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BandError::SchemaMismatch);
        }
        if self.lower >= self.upper {
            return Err(BandError::BadThresholds);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_to_high_at_upper() {
        let mut b = HysteresisBand::new(10, 20, State::Low).unwrap();
        assert_eq!(b.observe(15), State::Low);
        assert_eq!(b.observe(20), State::High);
    }

    #[test]
    fn high_to_low_at_lower() {
        let mut b = HysteresisBand::new(10, 20, State::High).unwrap();
        assert_eq!(b.observe(15), State::High);
        assert_eq!(b.observe(10), State::Low);
    }

    #[test]
    fn jitter_in_band_suppressed() {
        let mut b = HysteresisBand::new(10, 20, State::Low).unwrap();
        for s in [11, 19, 15, 12, 18] {
            assert_eq!(b.observe(s), State::Low);
        }
        assert_eq!(b.transitions, 0);
    }

    #[test]
    fn full_cycle_counts_transitions() {
        let mut b = HysteresisBand::new(10, 20, State::Low).unwrap();
        b.observe(25);
        b.observe(5);
        b.observe(25);
        assert_eq!(b.transitions, 3);
    }

    #[test]
    fn negative_thresholds() {
        let mut b = HysteresisBand::new(-20, -10, State::Low).unwrap();
        assert_eq!(b.observe(-10), State::High);
        assert_eq!(b.observe(-20), State::Low);
    }

    #[test]
    fn bad_thresholds_rejected() {
        assert!(matches!(
            HysteresisBand::new(10, 10, State::Low).unwrap_err(),
            BandError::BadThresholds
        ));
        assert!(matches!(
            HysteresisBand::new(20, 10, State::Low).unwrap_err(),
            BandError::BadThresholds
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut b = HysteresisBand::new(10, 20, State::Low).unwrap();
        b.schema_version = "9.9.9".into();
        assert!(matches!(
            b.validate().unwrap_err(),
            BandError::SchemaMismatch
        ));
    }

    #[test]
    fn band_serde_roundtrip() {
        let mut b = HysteresisBand::new(10, 20, State::Low).unwrap();
        b.observe(25);
        let j = serde_json::to_string(&b).unwrap();
        let back: HysteresisBand = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
