//! `selfdef-bounded-fifo` — capacity-bounded FIFO.
//!
//! Policy{DropOldest/Reject}. push: if at capacity, DropOldest
//! evicts head (returns it), Reject errors Full. pop removes
//! head; peek_head reads. Items are arbitrary strings.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Policy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Policy {
    /// Drop oldest at capacity.
    DropOldest,
    /// Reject new at capacity.
    Reject,
}

/// Push result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PushResult {
    /// Accepted; no eviction.
    Accepted,
    /// Accepted; this item was evicted.
    Evicted(String),
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BoundedFifo {
    /// Schema version.
    pub schema_version: String,
    /// Capacity.
    pub capacity: u32,
    /// Items (head first).
    pub items: Vec<String>,
    /// Policy.
    pub policy: Policy,
    /// Drops (DropOldest evictions + Reject rejections).
    pub drops: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum FifoError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("item empty")]
    EmptyItem,
    /// Zero capacity.
    #[error("capacity must be >= 1")]
    ZeroCapacity,
    /// Full.
    #[error("queue full")]
    Full,
}

impl BoundedFifo {
    /// New.
    pub fn new(capacity: u32, policy: Policy) -> Result<Self, FifoError> {
        if capacity == 0 { return Err(FifoError::ZeroCapacity); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            capacity,
            items: Vec::new(),
            policy,
            drops: 0,
        })
    }

    /// Push.
    pub fn push(&mut self, item: &str) -> Result<PushResult, FifoError> {
        if item.is_empty() { return Err(FifoError::EmptyItem); }
        if (self.items.len() as u32) >= self.capacity {
            match self.policy {
                Policy::DropOldest => {
                    let evicted = self.items.remove(0);
                    self.items.push(item.into());
                    self.drops = self.drops.saturating_add(1);
                    return Ok(PushResult::Evicted(evicted));
                }
                Policy::Reject => {
                    self.drops = self.drops.saturating_add(1);
                    return Err(FifoError::Full);
                }
            }
        }
        self.items.push(item.into());
        Ok(PushResult::Accepted)
    }

    /// Pop head.
    pub fn pop(&mut self) -> Option<String> {
        if self.items.is_empty() { None } else { Some(self.items.remove(0)) }
    }

    /// Peek head.
    pub fn peek_head(&self) -> Option<&str> { self.items.first().map(|s| s.as_str()) }

    /// Count.
    pub fn len(&self) -> usize { self.items.len() }

    /// Empty?
    pub fn is_empty(&self) -> bool { self.items.is_empty() }

    /// Validate.
    pub fn validate(&self) -> Result<(), FifoError> {
        if self.schema_version != SCHEMA_VERSION { return Err(FifoError::SchemaMismatch); }
        if self.capacity == 0 { return Err(FifoError::ZeroCapacity); }
        for i in &self.items {
            if i.is_empty() { return Err(FifoError::EmptyItem); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_and_pop_order() {
        let mut q = BoundedFifo::new(5, Policy::DropOldest).unwrap();
        q.push("a").unwrap();
        q.push("b").unwrap();
        q.push("c").unwrap();
        assert_eq!(q.pop(), Some("a".into()));
        assert_eq!(q.pop(), Some("b".into()));
        assert_eq!(q.pop(), Some("c".into()));
        assert!(q.pop().is_none());
    }

    #[test]
    fn drop_oldest_evicts() {
        let mut q = BoundedFifo::new(2, Policy::DropOldest).unwrap();
        q.push("a").unwrap();
        q.push("b").unwrap();
        let r = q.push("c").unwrap();
        assert_eq!(r, PushResult::Evicted("a".into()));
        assert_eq!(q.drops, 1);
        assert_eq!(q.peek_head(), Some("b"));
    }

    #[test]
    fn reject_errors_full() {
        let mut q = BoundedFifo::new(2, Policy::Reject).unwrap();
        q.push("a").unwrap();
        q.push("b").unwrap();
        assert!(matches!(q.push("c").unwrap_err(), FifoError::Full));
        assert_eq!(q.drops, 1);
    }

    #[test]
    fn peek_does_not_remove() {
        let mut q = BoundedFifo::new(5, Policy::DropOldest).unwrap();
        q.push("a").unwrap();
        assert_eq!(q.peek_head(), Some("a"));
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut q = BoundedFifo::new(2, Policy::DropOldest).unwrap();
        assert!(matches!(q.push("").unwrap_err(), FifoError::EmptyItem));
        assert!(matches!(BoundedFifo::new(0, Policy::DropOldest).unwrap_err(), FifoError::ZeroCapacity));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut q = BoundedFifo::new(2, Policy::DropOldest).unwrap();
        q.schema_version = "9.9.9".into();
        assert!(matches!(q.validate().unwrap_err(), FifoError::SchemaMismatch));
    }

    #[test]
    fn fifo_serde_roundtrip() {
        let mut q = BoundedFifo::new(2, Policy::Reject).unwrap();
        q.push("a").unwrap();
        let j = serde_json::to_string(&q).unwrap();
        let back: BoundedFifo = serde_json::from_str(&j).unwrap();
        assert_eq!(q, back);
    }
}
