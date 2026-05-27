//! `selfdef-cancel-set` — one-way cancellation flags.
//!
//! cancel(id, now, reason) sets the flag and records (ts,
//! reason). is_cancelled checks. reason(id) returns the
//! recorded reason. Flags are one-way (cannot un-cancel).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Cancellation record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CancelRecord {
    /// Ts ms.
    pub ts_ms: u64,
    /// Reason.
    pub reason: String,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CancelSet {
    /// Schema version.
    pub schema_version: String,
    /// id → record.
    pub cancelled: BTreeMap<String, CancelRecord>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CancelError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("id empty")]
    EmptyId,
    /// Empty.
    #[error("reason empty")]
    EmptyReason,
    /// Already.
    #[error("already cancelled: {0}")]
    AlreadyCancelled(String),
}

impl CancelSet {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            cancelled: BTreeMap::new(),
        }
    }

    /// Cancel.
    pub fn cancel(&mut self, id: &str, now_ms: u64, reason: &str) -> Result<(), CancelError> {
        if id.is_empty() {
            return Err(CancelError::EmptyId);
        }
        if reason.is_empty() {
            return Err(CancelError::EmptyReason);
        }
        if self.cancelled.contains_key(id) {
            return Err(CancelError::AlreadyCancelled(id.into()));
        }
        self.cancelled.insert(
            id.into(),
            CancelRecord {
                ts_ms: now_ms,
                reason: reason.into(),
            },
        );
        Ok(())
    }

    /// Cancelled?
    pub fn is_cancelled(&self, id: &str) -> bool {
        self.cancelled.contains_key(id)
    }

    /// Reason.
    pub fn reason(&self, id: &str) -> Option<&str> {
        self.cancelled.get(id).map(|r| r.reason.as_str())
    }

    /// Cancelled ids.
    pub fn ids(&self) -> Vec<&str> {
        self.cancelled.keys().map(|k| k.as_str()).collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CancelError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CancelError::SchemaMismatch);
        }
        for (k, v) in &self.cancelled {
            if k.is_empty() {
                return Err(CancelError::EmptyId);
            }
            if v.reason.is_empty() {
                return Err(CancelError::EmptyReason);
            }
        }
        Ok(())
    }
}

impl Default for CancelSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_records() {
        let mut c = CancelSet::new();
        c.cancel("a", 100, "user-abort").unwrap();
        assert!(c.is_cancelled("a"));
        assert_eq!(c.reason("a"), Some("user-abort"));
    }

    #[test]
    fn unknown_id_not_cancelled() {
        let c = CancelSet::new();
        assert!(!c.is_cancelled("nope"));
        assert!(c.reason("nope").is_none());
    }

    #[test]
    fn duplicate_cancel_rejected() {
        let mut c = CancelSet::new();
        c.cancel("a", 100, "x").unwrap();
        assert!(matches!(
            c.cancel("a", 200, "y").unwrap_err(),
            CancelError::AlreadyCancelled(_)
        ));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut c = CancelSet::new();
        assert!(matches!(
            c.cancel("", 0, "x").unwrap_err(),
            CancelError::EmptyId
        ));
        assert!(matches!(
            c.cancel("a", 0, "").unwrap_err(),
            CancelError::EmptyReason
        ));
    }

    #[test]
    fn ids_lists() {
        let mut c = CancelSet::new();
        c.cancel("a", 0, "x").unwrap();
        c.cancel("b", 0, "y").unwrap();
        let mut ids = c.ids();
        ids.sort();
        assert_eq!(ids, vec!["a", "b"]);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = CancelSet::new();
        c.schema_version = "9.9.9".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            CancelError::SchemaMismatch
        ));
    }

    #[test]
    fn set_serde_roundtrip() {
        let mut c = CancelSet::new();
        c.cancel("a", 100, "x").unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: CancelSet = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
