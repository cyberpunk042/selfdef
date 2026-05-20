//! `selfdef-inflight-set` — pending ids with deadlines.
//!
//! issue(id, now, ttl_ms) tracks an inflight id with deadline =
//! now + ttl. ack(id) removes (counted). sweep_timeouts(now)
//! removes entries past deadline and returns them. contains
//! and size queries. Pure data.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct InflightEntry {
    /// Issued ts ms.
    pub issued_ms: u64,
    /// Deadline ts ms.
    pub deadline_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InflightSet {
    /// Schema version.
    pub schema_version: String,
    /// id → entry.
    pub entries: BTreeMap<String, InflightEntry>,
    /// Total issued.
    pub issued: u64,
    /// Total acked.
    pub acked: u64,
    /// Total timed out.
    pub timed_out: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum InflightError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("id empty")]
    EmptyId,
    /// Zero ttl.
    #[error("ttl_ms must be >= 1")]
    ZeroTtl,
    /// Duplicate.
    #[error("duplicate inflight id: {0}")]
    DuplicateId(String),
}

impl InflightSet {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            entries: BTreeMap::new(),
            issued: 0,
            acked: 0,
            timed_out: 0,
        }
    }

    /// Issue an inflight id.
    pub fn issue(&mut self, id: &str, now_ms: u64, ttl_ms: u64) -> Result<(), InflightError> {
        if id.is_empty() { return Err(InflightError::EmptyId); }
        if ttl_ms == 0 { return Err(InflightError::ZeroTtl); }
        if self.entries.contains_key(id) {
            return Err(InflightError::DuplicateId(id.into()));
        }
        let deadline_ms = now_ms.saturating_add(ttl_ms);
        self.entries.insert(id.into(), InflightEntry { issued_ms: now_ms, deadline_ms });
        self.issued = self.issued.saturating_add(1);
        Ok(())
    }

    /// Ack an id.
    pub fn ack(&mut self, id: &str) -> bool {
        if self.entries.remove(id).is_some() {
            self.acked = self.acked.saturating_add(1);
            true
        } else {
            false
        }
    }

    /// Sweep entries past deadline; return their ids.
    pub fn sweep_timeouts(&mut self, now_ms: u64) -> Vec<String> {
        let stale: Vec<String> = self.entries
            .iter()
            .filter(|(_, e)| e.deadline_ms <= now_ms)
            .map(|(k, _)| k.clone())
            .collect();
        for k in &stale {
            self.entries.remove(k);
        }
        self.timed_out = self.timed_out.saturating_add(stale.len() as u64);
        stale
    }

    /// Contains?
    pub fn contains(&self, id: &str) -> bool {
        self.entries.contains_key(id)
    }

    /// Count.
    pub fn len(&self) -> usize { self.entries.len() }

    /// Empty.
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    /// Validate.
    pub fn validate(&self) -> Result<(), InflightError> {
        if self.schema_version != SCHEMA_VERSION { return Err(InflightError::SchemaMismatch); }
        for k in self.entries.keys() {
            if k.is_empty() { return Err(InflightError::EmptyId); }
        }
        Ok(())
    }
}

impl Default for InflightSet {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_ack() {
        let mut s = InflightSet::new();
        s.issue("a", 0, 1000).unwrap();
        assert!(s.contains("a"));
        assert!(s.ack("a"));
        assert!(!s.contains("a"));
        assert_eq!(s.acked, 1);
    }

    #[test]
    fn ack_unknown_returns_false() {
        let mut s = InflightSet::new();
        assert!(!s.ack("nope"));
    }

    #[test]
    fn timeout_sweep_returns_stale_ids() {
        let mut s = InflightSet::new();
        s.issue("a", 0, 100).unwrap();
        s.issue("b", 0, 1000).unwrap();
        let stale = s.sweep_timeouts(500);
        assert_eq!(stale, vec!["a"]);
        assert_eq!(s.timed_out, 1);
        assert!(!s.contains("a"));
        assert!(s.contains("b"));
    }

    #[test]
    fn duplicate_issue_rejected() {
        let mut s = InflightSet::new();
        s.issue("a", 0, 1000).unwrap();
        assert!(matches!(s.issue("a", 0, 1000).unwrap_err(), InflightError::DuplicateId(_)));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut s = InflightSet::new();
        assert!(matches!(s.issue("", 0, 1000).unwrap_err(), InflightError::EmptyId));
        assert!(matches!(s.issue("a", 0, 0).unwrap_err(), InflightError::ZeroTtl));
    }

    #[test]
    fn counts_track_correctly() {
        let mut s = InflightSet::new();
        s.issue("a", 0, 100).unwrap();
        s.issue("b", 0, 100).unwrap();
        s.ack("a");
        s.sweep_timeouts(200);
        assert_eq!(s.issued, 2);
        assert_eq!(s.acked, 1);
        assert_eq!(s.timed_out, 1);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = InflightSet::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), InflightError::SchemaMismatch));
    }

    #[test]
    fn set_serde_roundtrip() {
        let mut s = InflightSet::new();
        s.issue("a", 0, 1000).unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: InflightSet = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
