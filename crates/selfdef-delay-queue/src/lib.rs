//! `selfdef-delay-queue` — time-ordered delay queue.
//!
//! Entry{id, fire_at_ms, payload}. schedule appends and re-sorts;
//! poll(now_ms) drains entries with fire_at_ms <= now and returns
//! them. cancel(id) removes by id. next_fire returns the earliest
//! fire_at_ms without draining.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// Id.
    pub id: String,
    /// Fire ts ms.
    pub fire_at_ms: u64,
    /// Payload (free-form string).
    pub payload: String,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelayQueue {
    /// Schema version.
    pub schema_version: String,
    /// Entries sorted ascending by fire_at_ms.
    pub entries: Vec<Entry>,
    /// Drains performed.
    pub drains: u64,
    /// Cancellations.
    pub cancels: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum QueueError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("id empty")]
    EmptyId,
    /// Duplicate.
    #[error("duplicate id: {0}")]
    DuplicateId(String),
}

impl DelayQueue {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            entries: Vec::new(),
            drains: 0,
            cancels: 0,
        }
    }

    /// Schedule.
    pub fn schedule(&mut self, id: &str, fire_at_ms: u64, payload: &str) -> Result<(), QueueError> {
        if id.is_empty() { return Err(QueueError::EmptyId); }
        if self.entries.iter().any(|e| e.id == id) {
            return Err(QueueError::DuplicateId(id.into()));
        }
        let entry = Entry { id: id.into(), fire_at_ms, payload: payload.into() };
        // Binary-insert to keep sorted.
        let pos = self.entries.binary_search_by(|e| e.fire_at_ms.cmp(&fire_at_ms))
            .unwrap_or_else(|p| p);
        self.entries.insert(pos, entry);
        Ok(())
    }

    /// Cancel by id; true if removed.
    pub fn cancel(&mut self, id: &str) -> bool {
        if let Some(pos) = self.entries.iter().position(|e| e.id == id) {
            self.entries.remove(pos);
            self.cancels = self.cancels.saturating_add(1);
            true
        } else {
            false
        }
    }

    /// Drain entries with fire_at <= now.
    pub fn poll(&mut self, now_ms: u64) -> Vec<Entry> {
        let mut cut = 0usize;
        while cut < self.entries.len() && self.entries[cut].fire_at_ms <= now_ms {
            cut += 1;
        }
        let drained: Vec<Entry> = self.entries.drain(..cut).collect();
        if !drained.is_empty() {
            self.drains = self.drains.saturating_add(drained.len() as u64);
        }
        drained
    }

    /// Next fire ts (None if empty).
    pub fn next_fire(&self) -> Option<u64> {
        self.entries.first().map(|e| e.fire_at_ms)
    }

    /// Pending count.
    pub fn len(&self) -> usize { self.entries.len() }

    /// Empty.
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    /// Validate.
    pub fn validate(&self) -> Result<(), QueueError> {
        if self.schema_version != SCHEMA_VERSION { return Err(QueueError::SchemaMismatch); }
        for w in self.entries.windows(2) {
            if w[0].fire_at_ms > w[1].fire_at_ms {
                return Err(QueueError::EmptyId); // re-use as ordering error
            }
        }
        Ok(())
    }
}

impl Default for DelayQueue {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_no_next() {
        let q = DelayQueue::new();
        assert!(q.next_fire().is_none());
    }

    #[test]
    fn schedule_orders_by_fire_at() {
        let mut q = DelayQueue::new();
        q.schedule("c", 300, "x").unwrap();
        q.schedule("a", 100, "x").unwrap();
        q.schedule("b", 200, "x").unwrap();
        let ids: Vec<String> = q.entries.iter().map(|e| e.id.clone()).collect();
        assert_eq!(ids, vec!["a", "b", "c"]);
    }

    #[test]
    fn poll_drains_ready() {
        let mut q = DelayQueue::new();
        q.schedule("a", 100, "x").unwrap();
        q.schedule("b", 200, "y").unwrap();
        q.schedule("c", 500, "z").unwrap();
        let drained = q.poll(200);
        assert_eq!(drained.len(), 2);
        assert_eq!(q.len(), 1);
        assert_eq!(q.next_fire(), Some(500));
    }

    #[test]
    fn poll_nothing_when_no_ready() {
        let mut q = DelayQueue::new();
        q.schedule("a", 1000, "x").unwrap();
        let drained = q.poll(500);
        assert!(drained.is_empty());
    }

    #[test]
    fn cancel_removes() {
        let mut q = DelayQueue::new();
        q.schedule("a", 100, "x").unwrap();
        q.schedule("b", 200, "y").unwrap();
        assert!(q.cancel("a"));
        assert!(!q.cancel("a"));
        assert_eq!(q.next_fire(), Some(200));
    }

    #[test]
    fn duplicate_id_rejected() {
        let mut q = DelayQueue::new();
        q.schedule("a", 100, "x").unwrap();
        assert!(matches!(q.schedule("a", 200, "y").unwrap_err(), QueueError::DuplicateId(_)));
    }

    #[test]
    fn empty_id_rejected() {
        let mut q = DelayQueue::new();
        assert!(matches!(q.schedule("", 100, "x").unwrap_err(), QueueError::EmptyId));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut q = DelayQueue::new();
        q.schema_version = "9.9.9".into();
        assert!(matches!(q.validate().unwrap_err(), QueueError::SchemaMismatch));
    }

    #[test]
    fn queue_serde_roundtrip() {
        let mut q = DelayQueue::new();
        q.schedule("a", 100, "x").unwrap();
        let j = serde_json::to_string(&q).unwrap();
        let back: DelayQueue = serde_json::from_str(&j).unwrap();
        assert_eq!(q, back);
    }
}
