//! `selfdef-prefetch-queue` — dedup'd prefetch hint queue.
//!
//! hint(key) enqueues a prefetch request. Duplicate keys are
//! treated as the key being moved to the back (most-recent
//! hint wins). pop returns the oldest hint. capacity is bounded;
//! when full, oldest is evicted (LRU). All ops O(n) via VecDeque
//! — intended for modest queue sizes (tens to thousands).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrefetchQueue {
    /// Schema version.
    pub schema_version: String,
    /// Capacity (>= 1).
    pub capacity: u32,
    /// Queue (front = oldest hint).
    pub queue: VecDeque<String>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum PrefetchError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero capacity.
    #[error("capacity must be >= 1")]
    ZeroCap,
    /// Empty.
    #[error("key empty")]
    EmptyKey,
}

impl PrefetchQueue {
    /// New.
    pub fn new(capacity: u32) -> Result<Self, PrefetchError> {
        if capacity == 0 {
            return Err(PrefetchError::ZeroCap);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            capacity,
            queue: VecDeque::new(),
        })
    }

    /// Add a hint; dedup pushes existing entry to the back.
    pub fn hint(&mut self, key: &str) -> Result<(), PrefetchError> {
        if key.is_empty() {
            return Err(PrefetchError::EmptyKey);
        }
        // Remove existing same-key entry.
        if let Some(idx) = self.queue.iter().position(|x| x == key) {
            self.queue.remove(idx);
        }
        self.queue.push_back(key.into());
        // Enforce capacity by evicting from the front.
        while self.queue.len() > self.capacity as usize {
            self.queue.pop_front();
        }
        Ok(())
    }

    /// Pop the oldest hint.
    pub fn pop(&mut self) -> Option<String> {
        self.queue.pop_front()
    }

    /// Length.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), PrefetchError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(PrefetchError::SchemaMismatch);
        }
        if self.capacity == 0 {
            return Err(PrefetchError::ZeroCap);
        }
        for k in &self.queue {
            if k.is_empty() {
                return Err(PrefetchError::EmptyKey);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hint_and_pop_fifo() {
        let mut q = PrefetchQueue::new(10).unwrap();
        q.hint("a").unwrap();
        q.hint("b").unwrap();
        q.hint("c").unwrap();
        assert_eq!(q.pop(), Some("a".into()));
        assert_eq!(q.pop(), Some("b".into()));
        assert_eq!(q.pop(), Some("c".into()));
        assert_eq!(q.pop(), None);
    }

    #[test]
    fn dup_hint_moves_to_back() {
        let mut q = PrefetchQueue::new(10).unwrap();
        q.hint("a").unwrap();
        q.hint("b").unwrap();
        q.hint("a").unwrap(); // a is moved to back
        assert_eq!(q.pop(), Some("b".into()));
        assert_eq!(q.pop(), Some("a".into()));
    }

    #[test]
    fn lru_eviction_at_capacity() {
        let mut q = PrefetchQueue::new(2).unwrap();
        q.hint("a").unwrap();
        q.hint("b").unwrap();
        q.hint("c").unwrap(); // evicts a
        assert_eq!(q.pop(), Some("b".into()));
        assert_eq!(q.pop(), Some("c".into()));
    }

    #[test]
    fn len_tracks() {
        let mut q = PrefetchQueue::new(5).unwrap();
        q.hint("a").unwrap();
        q.hint("b").unwrap();
        assert_eq!(q.len(), 2);
        q.pop();
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn empty_key_rejected() {
        let mut q = PrefetchQueue::new(2).unwrap();
        assert!(matches!(q.hint("").unwrap_err(), PrefetchError::EmptyKey));
    }

    #[test]
    fn zero_capacity_rejected() {
        assert!(matches!(
            PrefetchQueue::new(0).unwrap_err(),
            PrefetchError::ZeroCap
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut q = PrefetchQueue::new(2).unwrap();
        q.schema_version = "9.9.9".into();
        assert!(matches!(
            q.validate().unwrap_err(),
            PrefetchError::SchemaMismatch
        ));
    }

    #[test]
    fn queue_serde_roundtrip() {
        let mut q = PrefetchQueue::new(5).unwrap();
        q.hint("x").unwrap();
        q.hint("y").unwrap();
        let j = serde_json::to_string(&q).unwrap();
        let back: PrefetchQueue = serde_json::from_str(&j).unwrap();
        assert_eq!(q, back);
    }
}
