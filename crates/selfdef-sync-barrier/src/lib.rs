//! `selfdef-sync-barrier` — N-party sync barrier.
//!
//! All `expected_parties` must arrive() before tripped() returns
//! true. Late arrivals after trip are rejected as AlreadyTripped.
//! Deadline transitions to TimedOut if not all arrive by deadline.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// Waiting for parties.
    Waiting,
    /// All parties arrived.
    Tripped,
    /// Timed out.
    TimedOut,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncBarrier {
    /// Schema version.
    pub schema_version: String,
    /// Expected party ids.
    pub expected: BTreeSet<String>,
    /// Arrived parties.
    pub arrived: BTreeSet<String>,
    /// Deadline ms.
    pub deadline_ms: u64,
    /// Status.
    pub status: Status,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BarrierError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("party id empty")]
    EmptyParty,
    /// Not expected.
    #[error("party not in expected set: {0}")]
    NotExpected(String),
    /// Already arrived.
    #[error("party already arrived: {0}")]
    AlreadyArrived(String),
    /// Already tripped.
    #[error("barrier already tripped")]
    AlreadyTripped,
}

impl SyncBarrier {
    /// New.
    pub fn new(expected: &[&str], deadline_ms: u64) -> Result<Self, BarrierError> {
        let mut set = BTreeSet::new();
        for p in expected {
            if p.is_empty() { return Err(BarrierError::EmptyParty); }
            set.insert((*p).into());
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            expected: set,
            arrived: BTreeSet::new(),
            deadline_ms,
            status: Status::Waiting,
        })
    }

    /// Arrive.
    pub fn arrive(&mut self, party: &str, now_ms: u64) -> Result<Status, BarrierError> {
        if party.is_empty() { return Err(BarrierError::EmptyParty); }
        // Check timeout first.
        if matches!(self.status, Status::Waiting) && now_ms >= self.deadline_ms {
            self.status = Status::TimedOut;
        }
        match self.status {
            Status::Tripped => return Err(BarrierError::AlreadyTripped),
            Status::TimedOut => return Ok(Status::TimedOut),
            Status::Waiting => {}
        }
        if !self.expected.contains(party) { return Err(BarrierError::NotExpected(party.into())); }
        if !self.arrived.insert(party.into()) {
            return Err(BarrierError::AlreadyArrived(party.into()));
        }
        if self.arrived == self.expected {
            self.status = Status::Tripped;
        }
        Ok(self.status)
    }

    /// Force-check timeout without arriving.
    pub fn check(&mut self, now_ms: u64) -> Status {
        if matches!(self.status, Status::Waiting) && now_ms >= self.deadline_ms {
            self.status = Status::TimedOut;
        }
        self.status
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BarrierError> {
        if self.schema_version != SCHEMA_VERSION { return Err(BarrierError::SchemaMismatch); }
        for p in self.expected.iter().chain(self.arrived.iter()) {
            if p.is_empty() { return Err(BarrierError::EmptyParty); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trips_when_all_arrive() {
        let mut b = SyncBarrier::new(&["a", "b", "c"], 1000).unwrap();
        b.arrive("a", 0).unwrap();
        b.arrive("b", 0).unwrap();
        assert_eq!(b.arrive("c", 0).unwrap(), Status::Tripped);
    }

    #[test]
    fn waiting_until_complete() {
        let mut b = SyncBarrier::new(&["a", "b"], 1000).unwrap();
        assert_eq!(b.arrive("a", 0).unwrap(), Status::Waiting);
    }

    #[test]
    fn not_expected_rejected() {
        let mut b = SyncBarrier::new(&["a"], 1000).unwrap();
        assert!(matches!(b.arrive("z", 0).unwrap_err(), BarrierError::NotExpected(_)));
    }

    #[test]
    fn already_arrived_rejected() {
        let mut b = SyncBarrier::new(&["a", "b"], 1000).unwrap();
        b.arrive("a", 0).unwrap();
        assert!(matches!(b.arrive("a", 0).unwrap_err(), BarrierError::AlreadyArrived(_)));
    }

    #[test]
    fn timeout_then_arrive_returns_timedout() {
        let mut b = SyncBarrier::new(&["a", "b"], 1000).unwrap();
        b.arrive("a", 0).unwrap();
        assert_eq!(b.arrive("b", 2000).unwrap(), Status::TimedOut);
    }

    #[test]
    fn arrive_after_trip_rejected() {
        let mut b = SyncBarrier::new(&["a"], 1000).unwrap();
        b.arrive("a", 0).unwrap();
        assert!(matches!(b.arrive("a", 0).unwrap_err(), BarrierError::AlreadyTripped));
    }

    #[test]
    fn check_advances_timeout() {
        let mut b = SyncBarrier::new(&["a"], 100).unwrap();
        assert_eq!(b.check(200), Status::TimedOut);
    }

    #[test]
    fn empty_party_rejected() {
        let mut b = SyncBarrier::new(&["a"], 100).unwrap();
        assert!(matches!(b.arrive("", 0).unwrap_err(), BarrierError::EmptyParty));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut b = SyncBarrier::new(&["a"], 100).unwrap();
        b.schema_version = "9.9.9".into();
        assert!(matches!(b.validate().unwrap_err(), BarrierError::SchemaMismatch));
    }

    #[test]
    fn barrier_serde_roundtrip() {
        let mut b = SyncBarrier::new(&["a", "b"], 1000).unwrap();
        b.arrive("a", 0).unwrap();
        let j = serde_json::to_string(&b).unwrap();
        let back: SyncBarrier = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
