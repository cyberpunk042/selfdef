//! `selfdef-dead-letter-queue` — bounded dead-letter queue.
//!
//! Entry{msg_id, attempts, last_error, last_attempted_at_ms,
//! payload_bytes}. enqueue(id, error, attempts, now, bytes)
//! adds; on capacity overflow, oldest (lowest last_attempted_at_ms)
//! is evicted. drain() returns a snapshot of entries (oldest first).
//! replay(id) removes an entry by id (e.g. before re-submission).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// Message id.
    pub msg_id: String,
    /// Total attempts.
    pub attempts: u32,
    /// Last error.
    pub last_error: String,
    /// Last-attempted ts ms.
    pub last_attempted_at_ms: u64,
    /// Payload bytes (informational; not stored).
    pub payload_bytes: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeadLetterQueue {
    /// Schema version.
    pub schema_version: String,
    /// Capacity.
    pub capacity: u32,
    /// Entries (front=oldest by last_attempted_at_ms).
    pub entries: VecDeque<Entry>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DlqError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero cap.
    #[error("capacity must be >= 1")]
    ZeroCap,
    /// Empty.
    #[error("msg_id empty")]
    EmptyMsg,
    /// Empty.
    #[error("error empty")]
    EmptyError,
    /// Unknown.
    #[error("msg_id not found: {0}")]
    NotFound(String),
}

impl DeadLetterQueue {
    /// New.
    pub fn new(capacity: u32) -> Result<Self, DlqError> {
        if capacity == 0 {
            return Err(DlqError::ZeroCap);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            capacity,
            entries: VecDeque::new(),
        })
    }

    /// Enqueue (or update if same msg_id already present).
    pub fn enqueue(
        &mut self,
        msg_id: &str,
        error: &str,
        attempts: u32,
        now_ms: u64,
        payload_bytes: u64,
    ) -> Result<(), DlqError> {
        if msg_id.is_empty() {
            return Err(DlqError::EmptyMsg);
        }
        if error.is_empty() {
            return Err(DlqError::EmptyError);
        }
        // If id exists, remove its old entry (we re-insert at the back).
        if let Some(idx) = self.entries.iter().position(|e| e.msg_id == msg_id) {
            self.entries.remove(idx);
        }
        self.entries.push_back(Entry {
            msg_id: msg_id.into(),
            attempts,
            last_error: error.into(),
            last_attempted_at_ms: now_ms,
            payload_bytes,
        });
        // Evict oldest if over capacity.
        while self.entries.len() > self.capacity as usize {
            self.entries.pop_front();
        }
        Ok(())
    }

    /// Replay (remove by id).
    pub fn replay(&mut self, msg_id: &str) -> Result<Entry, DlqError> {
        let idx = self
            .entries
            .iter()
            .position(|e| e.msg_id == msg_id)
            .ok_or_else(|| DlqError::NotFound(msg_id.into()))?;
        Ok(self.entries.remove(idx).unwrap())
    }

    /// Length.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Snapshot oldest-first.
    pub fn drain_snapshot(&self) -> Vec<Entry> {
        self.entries.iter().cloned().collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DlqError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(DlqError::SchemaMismatch);
        }
        if self.capacity == 0 {
            return Err(DlqError::ZeroCap);
        }
        for e in &self.entries {
            if e.msg_id.is_empty() {
                return Err(DlqError::EmptyMsg);
            }
            if e.last_error.is_empty() {
                return Err(DlqError::EmptyError);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enqueue_grows_until_cap() {
        let mut d = DeadLetterQueue::new(3).unwrap();
        d.enqueue("a", "x", 1, 100, 50).unwrap();
        d.enqueue("b", "y", 2, 200, 60).unwrap();
        assert_eq!(d.len(), 2);
    }

    #[test]
    fn over_cap_evicts_oldest() {
        let mut d = DeadLetterQueue::new(2).unwrap();
        d.enqueue("a", "x", 1, 100, 0).unwrap();
        d.enqueue("b", "y", 1, 200, 0).unwrap();
        d.enqueue("c", "z", 1, 300, 0).unwrap();
        assert_eq!(d.len(), 2);
        let snap = d.drain_snapshot();
        assert_eq!(snap[0].msg_id, "b");
        assert_eq!(snap[1].msg_id, "c");
    }

    #[test]
    fn re_enqueue_updates_and_moves_to_back() {
        let mut d = DeadLetterQueue::new(5).unwrap();
        d.enqueue("a", "x", 1, 100, 0).unwrap();
        d.enqueue("b", "y", 1, 200, 0).unwrap();
        d.enqueue("a", "x2", 5, 300, 0).unwrap();
        let snap = d.drain_snapshot();
        assert_eq!(snap[0].msg_id, "b");
        assert_eq!(snap[1].msg_id, "a");
        assert_eq!(snap[1].attempts, 5);
        assert_eq!(snap[1].last_error, "x2");
    }

    #[test]
    fn replay_removes() {
        let mut d = DeadLetterQueue::new(5).unwrap();
        d.enqueue("a", "x", 1, 100, 0).unwrap();
        let removed = d.replay("a").unwrap();
        assert_eq!(removed.msg_id, "a");
        assert!(d.is_empty());
        assert!(matches!(d.replay("a").unwrap_err(), DlqError::NotFound(_)));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut d = DeadLetterQueue::new(5).unwrap();
        assert!(matches!(
            d.enqueue("", "x", 1, 0, 0).unwrap_err(),
            DlqError::EmptyMsg
        ));
        assert!(matches!(
            d.enqueue("a", "", 1, 0, 0).unwrap_err(),
            DlqError::EmptyError
        ));
    }

    #[test]
    fn zero_capacity_rejected() {
        assert!(matches!(
            DeadLetterQueue::new(0).unwrap_err(),
            DlqError::ZeroCap
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut d = DeadLetterQueue::new(5).unwrap();
        d.schema_version = "9.9.9".into();
        assert!(matches!(
            d.validate().unwrap_err(),
            DlqError::SchemaMismatch
        ));
    }

    #[test]
    fn dlq_serde_roundtrip() {
        let mut d = DeadLetterQueue::new(5).unwrap();
        d.enqueue("a", "boom", 3, 100, 256).unwrap();
        let j = serde_json::to_string(&d).unwrap();
        let back: DeadLetterQueue = serde_json::from_str(&j).unwrap();
        assert_eq!(d, back);
    }
}
