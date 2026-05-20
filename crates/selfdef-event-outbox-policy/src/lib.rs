//! `selfdef-event-outbox-policy` — transactional-outbox ledger.
//!
//! `append(payload, ts)` returns the assigned monotonic `seq`.
//! `pending()` returns events not yet acknowledged.
//! `confirm(up_to_seq)` removes events whose seq ≤ up_to_seq.
//! Pure ledger; durable write pattern for at-least-once delivery.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    /// Monotonic seq.
    pub seq: u64,
    /// Payload (opaque to outbox).
    pub payload: String,
    /// Ts ms.
    pub ts_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventOutboxPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Pending events (ascending seq).
    pub pending: Vec<Event>,
    /// Next seq.
    pub next_seq: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum OutboxError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty payload.
    #[error("payload empty")]
    EmptyPayload,
}

impl EventOutboxPolicy {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            pending: Vec::new(),
            next_seq: 1,
        }
    }

    /// Append.
    pub fn append(&mut self, payload: &str, ts_ms: u64) -> Result<u64, OutboxError> {
        if payload.is_empty() { return Err(OutboxError::EmptyPayload); }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.pending.push(Event { seq, payload: payload.into(), ts_ms });
        Ok(seq)
    }

    /// Pending events.
    pub fn pending(&self) -> &[Event] { &self.pending }

    /// Confirm up to seq (inclusive).
    pub fn confirm(&mut self, up_to_seq: u64) -> usize {
        let before = self.pending.len();
        self.pending.retain(|e| e.seq > up_to_seq);
        before - self.pending.len()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), OutboxError> {
        if self.schema_version != SCHEMA_VERSION { return Err(OutboxError::SchemaMismatch); }
        for e in &self.pending {
            if e.payload.is_empty() { return Err(OutboxError::EmptyPayload); }
        }
        Ok(())
    }
}

impl Default for EventOutboxPolicy {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_assigns_monotonic_seq() {
        let mut o = EventOutboxPolicy::new();
        let a = o.append("x", 0).unwrap();
        let b = o.append("y", 1).unwrap();
        assert_eq!(a + 1, b);
        assert_eq!(o.pending().len(), 2);
    }

    #[test]
    fn confirm_removes_up_to_seq() {
        let mut o = EventOutboxPolicy::new();
        o.append("a", 0).unwrap();
        o.append("b", 1).unwrap();
        o.append("c", 2).unwrap();
        let removed = o.confirm(2);
        assert_eq!(removed, 2);
        assert_eq!(o.pending().len(), 1);
        assert_eq!(o.pending()[0].seq, 3);
    }

    #[test]
    fn confirm_zero_removes_nothing() {
        let mut o = EventOutboxPolicy::new();
        o.append("a", 0).unwrap();
        assert_eq!(o.confirm(0), 0);
    }

    #[test]
    fn confirm_high_removes_all() {
        let mut o = EventOutboxPolicy::new();
        o.append("a", 0).unwrap();
        o.append("b", 1).unwrap();
        assert_eq!(o.confirm(99), 2);
        assert!(o.pending().is_empty());
    }

    #[test]
    fn empty_payload_rejected() {
        let mut o = EventOutboxPolicy::new();
        assert!(matches!(o.append("", 0).unwrap_err(), OutboxError::EmptyPayload));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut o = EventOutboxPolicy::new();
        o.schema_version = "9.9.9".into();
        assert!(matches!(o.validate().unwrap_err(), OutboxError::SchemaMismatch));
    }

    #[test]
    fn outbox_serde_roundtrip() {
        let mut o = EventOutboxPolicy::new();
        o.append("x", 0).unwrap();
        let j = serde_json::to_string(&o).unwrap();
        let back: EventOutboxPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(o, back);
    }
}
