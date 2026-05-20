//! `selfdef-event-log` — append-only bounded log.
//!
//! append(payload) assigns next_seq, returns the seq.
//! Capacity-bounded: older entries are dropped (their seqs are
//! lost). since(cursor) returns entries with seq > cursor, in
//! seq order. Cursor of 0 returns everything still retained.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    /// Sequence id.
    pub seq: u64,
    /// Payload.
    pub payload: String,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventLog {
    /// Schema version.
    pub schema_version: String,
    /// Capacity.
    pub capacity: u32,
    /// Buffer (seq-ascending).
    pub events: Vec<Event>,
    /// Next seq to assign.
    pub next_seq: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum LogError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("payload empty")]
    EmptyPayload,
    /// Zero capacity.
    #[error("capacity must be >= 1")]
    ZeroCapacity,
}

impl EventLog {
    /// New.
    pub fn new(capacity: u32) -> Result<Self, LogError> {
        if capacity == 0 { return Err(LogError::ZeroCapacity); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            capacity,
            events: Vec::new(),
            next_seq: 1,
        })
    }

    /// Append; returns assigned seq.
    pub fn append(&mut self, payload: &str) -> Result<u64, LogError> {
        if payload.is_empty() { return Err(LogError::EmptyPayload); }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        if (self.events.len() as u32) >= self.capacity {
            self.events.remove(0);
        }
        self.events.push(Event { seq, payload: payload.into() });
        Ok(seq)
    }

    /// Events with seq > cursor.
    pub fn since(&self, cursor: u64) -> Vec<&Event> {
        self.events.iter().filter(|e| e.seq > cursor).collect()
    }

    /// Earliest retained seq (None if empty).
    pub fn earliest_seq(&self) -> Option<u64> { self.events.first().map(|e| e.seq) }

    /// Latest retained seq.
    pub fn latest_seq(&self) -> Option<u64> { self.events.last().map(|e| e.seq) }

    /// Count.
    pub fn len(&self) -> usize { self.events.len() }

    /// Empty?
    pub fn is_empty(&self) -> bool { self.events.is_empty() }

    /// Validate.
    pub fn validate(&self) -> Result<(), LogError> {
        if self.schema_version != SCHEMA_VERSION { return Err(LogError::SchemaMismatch); }
        if self.capacity == 0 { return Err(LogError::ZeroCapacity); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_assigns_seq() {
        let mut l = EventLog::new(5).unwrap();
        assert_eq!(l.append("a").unwrap(), 1);
        assert_eq!(l.append("b").unwrap(), 2);
        assert_eq!(l.append("c").unwrap(), 3);
    }

    #[test]
    fn since_cursor_filters() {
        let mut l = EventLog::new(5).unwrap();
        l.append("a").unwrap();
        l.append("b").unwrap();
        l.append("c").unwrap();
        let seqs: Vec<u64> = l.since(1).iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![2, 3]);
        assert_eq!(l.since(0).len(), 3);
        assert!(l.since(99).is_empty());
    }

    #[test]
    fn capacity_drops_oldest() {
        let mut l = EventLog::new(2).unwrap();
        l.append("a").unwrap();
        l.append("b").unwrap();
        l.append("c").unwrap();
        let seqs: Vec<u64> = l.events.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![2, 3]);
        assert_eq!(l.earliest_seq(), Some(2));
        assert_eq!(l.latest_seq(), Some(3));
    }

    #[test]
    fn cursor_past_drop_skips_dropped() {
        let mut l = EventLog::new(2).unwrap();
        l.append("a").unwrap(); // seq 1 (dropped soon)
        l.append("b").unwrap(); // 2
        l.append("c").unwrap(); // 3, drops 1
        // Consumer last saw seq 1; since(1) returns 2 + 3.
        let seqs: Vec<u64> = l.since(1).iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![2, 3]);
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut l = EventLog::new(5).unwrap();
        assert!(matches!(l.append("").unwrap_err(), LogError::EmptyPayload));
        assert!(matches!(EventLog::new(0).unwrap_err(), LogError::ZeroCapacity));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut l = EventLog::new(5).unwrap();
        l.schema_version = "9.9.9".into();
        assert!(matches!(l.validate().unwrap_err(), LogError::SchemaMismatch));
    }

    #[test]
    fn log_serde_roundtrip() {
        let mut l = EventLog::new(5).unwrap();
        l.append("a").unwrap();
        let j = serde_json::to_string(&l).unwrap();
        let back: EventLog = serde_json::from_str(&j).unwrap();
        assert_eq!(l, back);
    }
}
