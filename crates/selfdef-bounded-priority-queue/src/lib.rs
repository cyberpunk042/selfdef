//! `selfdef-bounded-priority-queue` — bounded priority queue.
//!
//! Item{id, priority, seq}. push(item) inserts; when full and
//! incoming priority > min-existing, the min item is evicted
//! (counted as drops). Otherwise the incoming item is itself
//! rejected as drop. pop() returns highest-priority item;
//! ties break by lower seq (FIFO).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Item.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Item {
    /// Id.
    pub id: String,
    /// Priority (higher = more important).
    pub priority: i32,
    /// Sequence number for FIFO tie-break.
    pub seq: u64,
}

/// Push outcome.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PushOutcome {
    /// Accepted (queue not full).
    Accepted,
    /// Accepted; an older item was evicted (its id).
    Evicted(String),
    /// Rejected (incoming priority not higher than min).
    Dropped,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BoundedPriorityQueue {
    /// Schema version.
    pub schema_version: String,
    /// Capacity (>=1).
    pub capacity: u32,
    /// Items (unsorted vec; sort on pop).
    pub items: Vec<Item>,
    /// Next sequence number.
    pub next_seq: u64,
    /// Drop counter (rejected + evicted).
    pub drops: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum QueueError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("id empty")]
    EmptyId,
    /// Zero capacity.
    #[error("capacity must be >= 1")]
    ZeroCapacity,
    /// Duplicate.
    #[error("duplicate id: {0}")]
    DuplicateId(String),
}

impl BoundedPriorityQueue {
    /// New.
    pub fn new(capacity: u32) -> Result<Self, QueueError> {
        if capacity == 0 { return Err(QueueError::ZeroCapacity); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            capacity,
            items: Vec::new(),
            next_seq: 0,
            drops: 0,
        })
    }

    /// Push item with given priority.
    pub fn push(&mut self, id: &str, priority: i32) -> Result<PushOutcome, QueueError> {
        if id.is_empty() { return Err(QueueError::EmptyId); }
        if self.items.iter().any(|i| i.id == id) {
            return Err(QueueError::DuplicateId(id.into()));
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        if (self.items.len() as u32) < self.capacity {
            self.items.push(Item { id: id.into(), priority, seq });
            return Ok(PushOutcome::Accepted);
        }
        // Full — find min priority (later seq breaks tie: keep older).
        let (min_idx, min_item) = self.items
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| a.priority.cmp(&b.priority).then(b.seq.cmp(&a.seq)))
            .unwrap();
        if priority > min_item.priority {
            let evicted_id = min_item.id.clone();
            self.items.swap_remove(min_idx);
            self.items.push(Item { id: id.into(), priority, seq });
            self.drops = self.drops.saturating_add(1);
            return Ok(PushOutcome::Evicted(evicted_id));
        }
        self.drops = self.drops.saturating_add(1);
        Ok(PushOutcome::Dropped)
    }

    /// Pop highest priority (ties: lower seq first).
    pub fn pop(&mut self) -> Option<Item> {
        if self.items.is_empty() { return None; }
        let (idx, _) = self.items
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.priority.cmp(&b.priority).then(b.seq.cmp(&a.seq)))
            .unwrap();
        Some(self.items.swap_remove(idx))
    }

    /// Peek without removing.
    pub fn peek(&self) -> Option<&Item> {
        self.items
            .iter()
            .max_by(|a, b| a.priority.cmp(&b.priority).then(b.seq.cmp(&a.seq)))
    }

    /// Size.
    pub fn len(&self) -> usize { self.items.len() }

    /// Empty.
    pub fn is_empty(&self) -> bool { self.items.is_empty() }

    /// Validate.
    pub fn validate(&self) -> Result<(), QueueError> {
        if self.schema_version != SCHEMA_VERSION { return Err(QueueError::SchemaMismatch); }
        if self.capacity == 0 { return Err(QueueError::ZeroCapacity); }
        for i in &self.items {
            if i.id.is_empty() { return Err(QueueError::EmptyId); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_to_capacity() {
        let mut q = BoundedPriorityQueue::new(3).unwrap();
        assert_eq!(q.push("a", 1).unwrap(), PushOutcome::Accepted);
        assert_eq!(q.push("b", 2).unwrap(), PushOutcome::Accepted);
        assert_eq!(q.push("c", 3).unwrap(), PushOutcome::Accepted);
        assert_eq!(q.len(), 3);
    }

    #[test]
    fn higher_priority_evicts_lower() {
        let mut q = BoundedPriorityQueue::new(2).unwrap();
        q.push("a", 1).unwrap();
        q.push("b", 2).unwrap();
        let out = q.push("c", 5).unwrap();
        assert_eq!(out, PushOutcome::Evicted("a".into()));
        assert_eq!(q.drops, 1);
    }

    #[test]
    fn lower_priority_dropped_when_full() {
        let mut q = BoundedPriorityQueue::new(2).unwrap();
        q.push("a", 5).unwrap();
        q.push("b", 5).unwrap();
        let out = q.push("c", 1).unwrap();
        assert_eq!(out, PushOutcome::Dropped);
        assert_eq!(q.len(), 2);
        assert_eq!(q.drops, 1);
    }

    #[test]
    fn pop_returns_highest_priority() {
        let mut q = BoundedPriorityQueue::new(3).unwrap();
        q.push("a", 1).unwrap();
        q.push("b", 5).unwrap();
        q.push("c", 3).unwrap();
        assert_eq!(q.pop().unwrap().id, "b");
        assert_eq!(q.pop().unwrap().id, "c");
        assert_eq!(q.pop().unwrap().id, "a");
        assert!(q.pop().is_none());
    }

    #[test]
    fn ties_break_fifo() {
        let mut q = BoundedPriorityQueue::new(3).unwrap();
        q.push("a", 5).unwrap();
        q.push("b", 5).unwrap();
        q.push("c", 5).unwrap();
        assert_eq!(q.pop().unwrap().id, "a"); // earliest seq
    }

    #[test]
    fn peek_does_not_remove() {
        let mut q = BoundedPriorityQueue::new(3).unwrap();
        q.push("a", 1).unwrap();
        q.push("b", 5).unwrap();
        assert_eq!(q.peek().unwrap().id, "b");
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn duplicate_id_rejected() {
        let mut q = BoundedPriorityQueue::new(3).unwrap();
        q.push("a", 1).unwrap();
        assert!(matches!(q.push("a", 2).unwrap_err(), QueueError::DuplicateId(_)));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut q = BoundedPriorityQueue::new(3).unwrap();
        assert!(matches!(q.push("", 1).unwrap_err(), QueueError::EmptyId));
        assert!(matches!(BoundedPriorityQueue::new(0).unwrap_err(), QueueError::ZeroCapacity));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut q = BoundedPriorityQueue::new(3).unwrap();
        q.schema_version = "9.9.9".into();
        assert!(matches!(q.validate().unwrap_err(), QueueError::SchemaMismatch));
    }

    #[test]
    fn queue_serde_roundtrip() {
        let mut q = BoundedPriorityQueue::new(3).unwrap();
        q.push("a", 1).unwrap();
        let j = serde_json::to_string(&q).unwrap();
        let back: BoundedPriorityQueue = serde_json::from_str(&j).unwrap();
        assert_eq!(q, back);
    }
}
