//! `selfdef-delivery-ack-tracker` — per-message ack/nack state.
//!
//! `enqueue(message_id, max_retries)` registers a message awaiting
//! acknowledgement. `ack(message_id)` marks Delivered. `nack(
//! message_id)` either decrements retries (leaving Pending) or
//! transitions to DeadLetter when budget is exhausted.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Status of a message.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// Pending.
    Pending,
    /// Delivered.
    Delivered,
    /// Dead-letter (exhausted retries).
    DeadLetter,
}

/// Per-message record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageEntry {
    /// Status.
    pub status: Status,
    /// Retries remaining.
    pub retries_left: u32,
    /// Total retries observed.
    pub retry_count: u32,
    /// Last nack reason.
    pub last_nack_reason: Option<String>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeliveryAckTracker {
    /// Schema version.
    pub schema_version: String,
    /// id → entry.
    pub messages: BTreeMap<String, MessageEntry>,
    /// Total delivered.
    pub total_delivered: u64,
    /// Total dead-lettered.
    pub total_deadletter: u64,
}

/// Ack/nack verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum NackVerdict {
    /// Retried.
    Retried {
        /// remaining.
        retries_left: u32,
    },
    /// Dead-lettered (no more retries).
    DeadLettered,
}

/// Errors.
#[derive(Debug, Error)]
pub enum AckError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("id empty")]
    EmptyId,
    /// Empty reason.
    #[error("reason empty")]
    EmptyReason,
    /// Duplicate.
    #[error("duplicate message id: {0}")]
    DuplicateId(String),
    /// Unknown.
    #[error("unknown message: {0}")]
    UnknownMessage(String),
    /// Already terminal.
    #[error("message {0} not pending")]
    NotPending(String),
}

impl DeliveryAckTracker {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            messages: BTreeMap::new(),
            total_delivered: 0,
            total_deadletter: 0,
        }
    }

    /// Enqueue.
    pub fn enqueue(&mut self, message_id: &str, max_retries: u32) -> Result<(), AckError> {
        if message_id.is_empty() {
            return Err(AckError::EmptyId);
        }
        if self.messages.contains_key(message_id) {
            return Err(AckError::DuplicateId(message_id.into()));
        }
        self.messages.insert(
            message_id.into(),
            MessageEntry {
                status: Status::Pending,
                retries_left: max_retries,
                retry_count: 0,
                last_nack_reason: None,
            },
        );
        Ok(())
    }

    /// Ack.
    pub fn ack(&mut self, message_id: &str) -> Result<(), AckError> {
        let m = self
            .messages
            .get_mut(message_id)
            .ok_or_else(|| AckError::UnknownMessage(message_id.into()))?;
        if m.status != Status::Pending {
            return Err(AckError::NotPending(message_id.into()));
        }
        m.status = Status::Delivered;
        self.total_delivered = self.total_delivered.saturating_add(1);
        Ok(())
    }

    /// Nack.
    pub fn nack(&mut self, message_id: &str, reason: &str) -> Result<NackVerdict, AckError> {
        if reason.is_empty() {
            return Err(AckError::EmptyReason);
        }
        let m = self
            .messages
            .get_mut(message_id)
            .ok_or_else(|| AckError::UnknownMessage(message_id.into()))?;
        if m.status != Status::Pending {
            return Err(AckError::NotPending(message_id.into()));
        }
        m.last_nack_reason = Some(reason.into());
        m.retry_count = m.retry_count.saturating_add(1);
        if m.retries_left == 0 {
            m.status = Status::DeadLetter;
            self.total_deadletter = self.total_deadletter.saturating_add(1);
            Ok(NackVerdict::DeadLettered)
        } else {
            m.retries_left -= 1;
            Ok(NackVerdict::Retried {
                retries_left: m.retries_left,
            })
        }
    }

    /// Status snapshot.
    pub fn status(&self, message_id: &str) -> Option<Status> {
        self.messages.get(message_id).map(|m| m.status)
    }

    /// Pending count.
    pub fn pending_count(&self) -> usize {
        self.messages
            .values()
            .filter(|m| m.status == Status::Pending)
            .count()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), AckError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(AckError::SchemaMismatch);
        }
        for k in self.messages.keys() {
            if k.is_empty() {
                return Err(AckError::EmptyId);
            }
        }
        Ok(())
    }
}

impl Default for DeliveryAckTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_after_enqueue() {
        let mut t = DeliveryAckTracker::new();
        t.enqueue("m1", 3).unwrap();
        t.ack("m1").unwrap();
        assert_eq!(t.status("m1"), Some(Status::Delivered));
        assert_eq!(t.total_delivered, 1);
    }

    #[test]
    fn nack_retries_then_dead_letters() {
        let mut t = DeliveryAckTracker::new();
        t.enqueue("m1", 2).unwrap();
        match t.nack("m1", "timeout").unwrap() {
            NackVerdict::Retried { retries_left } => assert_eq!(retries_left, 1),
            _ => panic!(),
        }
        match t.nack("m1", "timeout").unwrap() {
            NackVerdict::Retried { retries_left } => assert_eq!(retries_left, 0),
            _ => panic!(),
        }
        // Third nack — retries_left was 0, dead letter.
        assert_eq!(t.nack("m1", "timeout").unwrap(), NackVerdict::DeadLettered);
        assert_eq!(t.status("m1"), Some(Status::DeadLetter));
    }

    #[test]
    fn double_ack_rejected() {
        let mut t = DeliveryAckTracker::new();
        t.enqueue("m1", 3).unwrap();
        t.ack("m1").unwrap();
        assert!(matches!(t.ack("m1").unwrap_err(), AckError::NotPending(_)));
    }

    #[test]
    fn ack_after_deadletter_rejected() {
        let mut t = DeliveryAckTracker::new();
        t.enqueue("m1", 0).unwrap();
        t.nack("m1", "fail").unwrap();
        assert!(matches!(t.ack("m1").unwrap_err(), AckError::NotPending(_)));
    }

    #[test]
    fn duplicate_enqueue_rejected() {
        let mut t = DeliveryAckTracker::new();
        t.enqueue("m1", 1).unwrap();
        assert!(matches!(
            t.enqueue("m1", 1).unwrap_err(),
            AckError::DuplicateId(_)
        ));
    }

    #[test]
    fn unknown_message_rejected() {
        let mut t = DeliveryAckTracker::new();
        assert!(matches!(
            t.ack("nope").unwrap_err(),
            AckError::UnknownMessage(_)
        ));
        assert!(matches!(
            t.nack("nope", "x").unwrap_err(),
            AckError::UnknownMessage(_)
        ));
    }

    #[test]
    fn pending_count() {
        let mut t = DeliveryAckTracker::new();
        t.enqueue("a", 1).unwrap();
        t.enqueue("b", 1).unwrap();
        t.ack("a").unwrap();
        assert_eq!(t.pending_count(), 1);
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut t = DeliveryAckTracker::new();
        assert!(matches!(t.enqueue("", 1).unwrap_err(), AckError::EmptyId));
        t.enqueue("a", 1).unwrap();
        assert!(matches!(
            t.nack("a", "").unwrap_err(),
            AckError::EmptyReason
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = DeliveryAckTracker::new();
        t.schema_version = "9.9.9".into();
        assert!(matches!(
            t.validate().unwrap_err(),
            AckError::SchemaMismatch
        ));
    }

    #[test]
    fn ack_serde_roundtrip() {
        let mut t = DeliveryAckTracker::new();
        t.enqueue("a", 3).unwrap();
        t.nack("a", "x").unwrap();
        let j = serde_json::to_string(&t).unwrap();
        let back: DeliveryAckTracker = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
