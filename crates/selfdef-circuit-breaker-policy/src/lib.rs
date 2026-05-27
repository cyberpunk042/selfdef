//! `selfdef-circuit-breaker-policy` — per-subject 3-state breaker.
//!
//! States:
//! * Closed — admit all; on K failures in last N outcomes → Open.
//! * Open — deny all; after open_for_seconds → HalfOpen.
//! * HalfOpen — admit ONE trial; success → Closed (reset window),
//!   failure → Open again.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BreakerState {
    /// Closed (normal).
    Closed,
    /// Open (deny).
    Open,
    /// HalfOpen (one trial).
    HalfOpen,
}

/// Outcome of an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    /// Success.
    Success,
    /// Failure.
    Failure,
}

/// Admit decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdmitDecision {
    /// Closed — admit.
    Allow,
    /// Open — refuse.
    Deny,
    /// HalfOpen — allow this one trial.
    Trial,
}

/// One breaker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Breaker {
    /// Subject id.
    pub subject: String,
    /// Window size for outcomes.
    pub window_size: u32,
    /// Failure count threshold within window to trip.
    pub failure_threshold: u32,
    /// How long Open lasts before transitioning to HalfOpen.
    pub open_for_seconds: u32,
    /// Current state.
    pub state: BreakerState,
    /// Recent outcomes (FIFO, last N).
    pub recent: Vec<Outcome>,
    /// Unix second when Open began (used to compute HalfOpen transition).
    pub opened_at_unix: u64,
    /// HalfOpen has already issued its trial?
    pub half_open_trial_taken: bool,
}

/// Policy envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CircuitBreakerPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Breakers.
    pub breakers: Vec<Breaker>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BreakerError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty subject.
    #[error("subject empty")]
    EmptySubject,
    /// Duplicate.
    #[error("duplicate subject: {0}")]
    DuplicateSubject(String),
    /// Threshold > window.
    #[error("subject {0}: failure_threshold > window_size")]
    ThresholdExceedsWindow(String),
    /// Zero param.
    #[error("subject {0}: {1} is zero")]
    ZeroParam(String, &'static str),
    /// Unknown subject.
    #[error("unknown subject: {0}")]
    Unknown(String),
}

impl CircuitBreakerPolicy {
    /// New empty.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            breakers: Vec::new(),
        }
    }

    /// Register.
    pub fn register(
        &mut self,
        subject: &str,
        window_size: u32,
        failure_threshold: u32,
        open_for_seconds: u32,
    ) -> Result<(), BreakerError> {
        if subject.is_empty() {
            return Err(BreakerError::EmptySubject);
        }
        if window_size == 0 {
            return Err(BreakerError::ZeroParam(subject.into(), "window_size"));
        }
        if failure_threshold == 0 {
            return Err(BreakerError::ZeroParam(subject.into(), "failure_threshold"));
        }
        if open_for_seconds == 0 {
            return Err(BreakerError::ZeroParam(subject.into(), "open_for_seconds"));
        }
        if failure_threshold > window_size {
            return Err(BreakerError::ThresholdExceedsWindow(subject.into()));
        }
        if self.breakers.iter().any(|b| b.subject == subject) {
            return Err(BreakerError::DuplicateSubject(subject.into()));
        }
        self.breakers.push(Breaker {
            subject: subject.into(),
            window_size,
            failure_threshold,
            open_for_seconds,
            state: BreakerState::Closed,
            recent: Vec::new(),
            opened_at_unix: 0,
            half_open_trial_taken: false,
        });
        Ok(())
    }

    /// Admit query (drives Open → HalfOpen transition by timeout).
    pub fn admit(&mut self, subject: &str, now: u64) -> Result<AdmitDecision, BreakerError> {
        let b = self
            .breakers
            .iter_mut()
            .find(|b| b.subject == subject)
            .ok_or_else(|| BreakerError::Unknown(subject.into()))?;
        // Tick Open → HalfOpen if timeout elapsed.
        if b.state == BreakerState::Open
            && now.saturating_sub(b.opened_at_unix) >= b.open_for_seconds as u64
        {
            b.state = BreakerState::HalfOpen;
            b.half_open_trial_taken = false;
        }
        Ok(match b.state {
            BreakerState::Closed => AdmitDecision::Allow,
            BreakerState::Open => AdmitDecision::Deny,
            BreakerState::HalfOpen => {
                if b.half_open_trial_taken {
                    AdmitDecision::Deny
                } else {
                    b.half_open_trial_taken = true;
                    AdmitDecision::Trial
                }
            }
        })
    }

    /// Record outcome and possibly transition state.
    pub fn record_outcome(
        &mut self,
        subject: &str,
        outcome: Outcome,
        now: u64,
    ) -> Result<BreakerState, BreakerError> {
        let b = self
            .breakers
            .iter_mut()
            .find(|b| b.subject == subject)
            .ok_or_else(|| BreakerError::Unknown(subject.into()))?;
        match b.state {
            BreakerState::Closed => {
                b.recent.push(outcome);
                while (b.recent.len() as u32) > b.window_size {
                    b.recent.remove(0);
                }
                let fails = b.recent.iter().filter(|o| **o == Outcome::Failure).count() as u32;
                if fails >= b.failure_threshold {
                    b.state = BreakerState::Open;
                    b.opened_at_unix = now;
                }
            }
            BreakerState::HalfOpen => match outcome {
                Outcome::Success => {
                    b.state = BreakerState::Closed;
                    b.recent.clear();
                    b.half_open_trial_taken = false;
                }
                Outcome::Failure => {
                    b.state = BreakerState::Open;
                    b.opened_at_unix = now;
                    b.half_open_trial_taken = false;
                }
            },
            BreakerState::Open => {
                // Should not happen in normal flow — but record nothing.
            }
        }
        Ok(b.state)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BreakerError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BreakerError::SchemaMismatch);
        }
        use std::collections::HashSet;
        let mut seen: HashSet<&str> = HashSet::new();
        for b in &self.breakers {
            if b.subject.is_empty() {
                return Err(BreakerError::EmptySubject);
            }
            if !seen.insert(b.subject.as_str()) {
                return Err(BreakerError::DuplicateSubject(b.subject.clone()));
            }
            if b.window_size == 0 {
                return Err(BreakerError::ZeroParam(b.subject.clone(), "window_size"));
            }
            if b.failure_threshold == 0 {
                return Err(BreakerError::ZeroParam(
                    b.subject.clone(),
                    "failure_threshold",
                ));
            }
            if b.open_for_seconds == 0 {
                return Err(BreakerError::ZeroParam(
                    b.subject.clone(),
                    "open_for_seconds",
                ));
            }
            if b.failure_threshold > b.window_size {
                return Err(BreakerError::ThresholdExceedsWindow(b.subject.clone()));
            }
        }
        Ok(())
    }
}

impl Default for CircuitBreakerPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> CircuitBreakerPolicy {
        let mut p = CircuitBreakerPolicy::new();
        p.register("api", 5, 3, 10).unwrap();
        p
    }

    #[test]
    fn closed_admits_allow() {
        let mut p = p();
        assert_eq!(p.admit("api", 0).unwrap(), AdmitDecision::Allow);
    }

    #[test]
    fn unknown_subject_rejected() {
        let mut p = p();
        assert!(matches!(
            p.admit("none", 0).unwrap_err(),
            BreakerError::Unknown(_)
        ));
    }

    #[test]
    fn trips_after_threshold_failures() {
        let mut p = p();
        for _ in 0..3 {
            p.record_outcome("api", Outcome::Failure, 100).unwrap();
        }
        assert_eq!(p.admit("api", 100).unwrap(), AdmitDecision::Deny);
    }

    #[test]
    fn open_transitions_to_half_open_after_timeout() {
        let mut p = p();
        for _ in 0..3 {
            p.record_outcome("api", Outcome::Failure, 100).unwrap();
        }
        // Within open window.
        assert_eq!(p.admit("api", 105).unwrap(), AdmitDecision::Deny);
        // After timeout (10s).
        let d = p.admit("api", 111).unwrap();
        assert_eq!(d, AdmitDecision::Trial);
    }

    #[test]
    fn half_open_second_request_denied() {
        let mut p = p();
        for _ in 0..3 {
            p.record_outcome("api", Outcome::Failure, 100).unwrap();
        }
        let _ = p.admit("api", 111).unwrap(); // Trial
        assert_eq!(p.admit("api", 111).unwrap(), AdmitDecision::Deny);
    }

    #[test]
    fn half_open_success_closes() {
        let mut p = p();
        for _ in 0..3 {
            p.record_outcome("api", Outcome::Failure, 100).unwrap();
        }
        p.admit("api", 111).unwrap();
        let state = p.record_outcome("api", Outcome::Success, 111).unwrap();
        assert_eq!(state, BreakerState::Closed);
        assert_eq!(p.admit("api", 112).unwrap(), AdmitDecision::Allow);
    }

    #[test]
    fn half_open_failure_re_opens() {
        let mut p = p();
        for _ in 0..3 {
            p.record_outcome("api", Outcome::Failure, 100).unwrap();
        }
        p.admit("api", 111).unwrap();
        let state = p.record_outcome("api", Outcome::Failure, 111).unwrap();
        assert_eq!(state, BreakerState::Open);
    }

    #[test]
    fn window_evicts_old_failures() {
        let mut p = p();
        // 2 failures, then 3 successes -> window full of 5; failures = 2.
        p.record_outcome("api", Outcome::Failure, 100).unwrap();
        p.record_outcome("api", Outcome::Failure, 100).unwrap();
        for _ in 0..3 {
            p.record_outcome("api", Outcome::Success, 100).unwrap();
        }
        // No trip.
        assert_eq!(p.admit("api", 100).unwrap(), AdmitDecision::Allow);
    }

    #[test]
    fn threshold_over_window_rejected() {
        let mut p = CircuitBreakerPolicy::new();
        assert!(matches!(
            p.register("x", 3, 5, 10).unwrap_err(),
            BreakerError::ThresholdExceedsWindow(_)
        ));
    }

    #[test]
    fn duplicate_subject_rejected() {
        let mut p = p();
        assert!(matches!(
            p.register("api", 5, 3, 10).unwrap_err(),
            BreakerError::DuplicateSubject(_)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = p();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            BreakerError::SchemaMismatch
        ));
    }

    #[test]
    fn state_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&BreakerState::HalfOpen).unwrap(),
            "\"half-open\""
        );
    }

    #[test]
    fn policy_serde_roundtrip() {
        let mut p = p();
        p.record_outcome("api", Outcome::Failure, 100).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: CircuitBreakerPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
