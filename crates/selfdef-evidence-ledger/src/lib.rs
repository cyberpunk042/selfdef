//! `selfdef-evidence-ledger` — MS040 gate-evidence durable record.
//!
//! Per MS040 R09408-R09410:
//! - Gate evidence retained 100 days (R09408)
//! - Indexed by trace-id (R09409)
//! - Indexed by actor (R09410)
//!
//! Composes selfdef-profile-authority-gate::Evidence as the carried
//! payload; this crate adds the index + retention discipline + lookup
//! API the daemon needs to satisfy operator inquiries.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_profile_authority_gate::Evidence;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Canonical 100-day retention window in seconds per R09408.
pub const RETENTION_SECONDS: u64 = 100 * 86_400;

/// One ledger record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerRecord {
    /// M049 trace_id (primary index, R09409).
    pub trace_id: String,
    /// Actor MS003 fingerprint (secondary index, R09410).
    pub actor: String,
    /// Recorded evidence payload.
    pub evidence: Evidence,
    /// ISO-8601 UTC of record.
    pub recorded_at: String,
    /// Unix-epoch seconds of record (for retention age math).
    pub recorded_epoch_seconds: u64,
}

/// Ledger envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceLedger {
    /// Schema version.
    pub schema_version: String,
    /// Records indexed by trace_id (primary).
    pub records: BTreeMap<String, LedgerRecord>,
}

impl Default for EvidenceLedger {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            records: BTreeMap::new(),
        }
    }
}

/// Errors.
#[derive(Debug, Error)]
pub enum LedgerError {
    /// Schema drift.
    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected.
        expected: String,
        /// Observed.
        actual: String,
    },
    /// Trace-id duplicate insert.
    #[error("duplicate trace_id: {0}")]
    DuplicateTraceId(String),
    /// Record not found by trace_id.
    #[error("record not found: trace_id {0}")]
    NotFoundByTraceId(String),
    /// Empty fields rejected.
    #[error("required field empty: {0}")]
    FieldEmpty(&'static str),
}

impl EvidenceLedger {
    /// Insert a new record. Duplicates rejected.
    pub fn insert(&mut self, rec: LedgerRecord) -> Result<(), LedgerError> {
        if rec.trace_id.is_empty() {
            return Err(LedgerError::FieldEmpty("trace_id"));
        }
        if rec.actor.is_empty() {
            return Err(LedgerError::FieldEmpty("actor"));
        }
        if self.records.contains_key(&rec.trace_id) {
            return Err(LedgerError::DuplicateTraceId(rec.trace_id));
        }
        self.records.insert(rec.trace_id.clone(), rec);
        Ok(())
    }

    /// Lookup by trace_id (R09409).
    pub fn find_by_trace_id(&self, trace_id: &str) -> Result<&LedgerRecord, LedgerError> {
        self.records
            .get(trace_id)
            .ok_or_else(|| LedgerError::NotFoundByTraceId(trace_id.into()))
    }

    /// Lookup by actor (R09410). Returns all matching records.
    pub fn find_by_actor(&self, actor: &str) -> Vec<&LedgerRecord> {
        self.records.values().filter(|r| r.actor == actor).collect()
    }

    /// Purge records older than RETENTION_SECONDS given the current epoch.
    /// Returns count purged.
    pub fn purge_expired(&mut self, now_epoch_seconds: u64) -> usize {
        let cutoff = now_epoch_seconds.saturating_sub(RETENTION_SECONDS);
        let to_remove: Vec<String> = self
            .records
            .iter()
            .filter(|(_, r)| r.recorded_epoch_seconds < cutoff)
            .map(|(k, _)| k.clone())
            .collect();
        let count = to_remove.len();
        for k in to_remove {
            self.records.remove(&k);
        }
        count
    }

    /// Total record count.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Validate envelope.
    pub fn validate(&self) -> Result<(), LedgerError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(LedgerError::SchemaMismatch {
                expected: SCHEMA_VERSION.into(),
                actual: self.schema_version.clone(),
            });
        }
        for (key, rec) in &self.records {
            if key != &rec.trace_id {
                return Err(LedgerError::FieldEmpty("trace_id-key-mismatch"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(trace_id: &str, actor: &str, epoch: u64) -> LedgerRecord {
        LedgerRecord {
            trace_id: trace_id.into(),
            actor: actor.into(),
            evidence: Evidence::default(),
            recorded_at: "2026-05-19T03:00:00Z".into(),
            recorded_epoch_seconds: epoch,
        }
    }

    #[test]
    fn insert_and_find_by_trace_id() {
        let mut l = EvidenceLedger::default();
        l.insert(rec("t1", "op", 1000)).unwrap();
        assert_eq!(l.find_by_trace_id("t1").unwrap().actor, "op");
    }

    #[test]
    fn missing_trace_id_lookup_errors() {
        let l = EvidenceLedger::default();
        assert!(matches!(
            l.find_by_trace_id("ghost").unwrap_err(),
            LedgerError::NotFoundByTraceId(_)
        ));
    }

    #[test]
    fn empty_trace_id_rejected() {
        let mut l = EvidenceLedger::default();
        assert!(matches!(
            l.insert(rec("", "op", 1000)).unwrap_err(),
            LedgerError::FieldEmpty("trace_id")
        ));
    }

    #[test]
    fn empty_actor_rejected() {
        let mut l = EvidenceLedger::default();
        assert!(matches!(
            l.insert(rec("t1", "", 1000)).unwrap_err(),
            LedgerError::FieldEmpty("actor")
        ));
    }

    #[test]
    fn duplicate_trace_id_rejected() {
        let mut l = EvidenceLedger::default();
        l.insert(rec("t1", "op", 1000)).unwrap();
        assert!(matches!(
            l.insert(rec("t1", "op2", 1100)).unwrap_err(),
            LedgerError::DuplicateTraceId(_)
        ));
    }

    #[test]
    fn find_by_actor_returns_multiple() {
        let mut l = EvidenceLedger::default();
        l.insert(rec("t1", "op", 1000)).unwrap();
        l.insert(rec("t2", "op", 1100)).unwrap();
        l.insert(rec("t3", "other", 1200)).unwrap();
        let found = l.find_by_actor("op");
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn purge_expired_removes_old_records() {
        let mut l = EvidenceLedger::default();
        l.insert(rec("t-old", "op", 0)).unwrap();
        l.insert(rec("t-recent", "op", 1_000_000_000)).unwrap();
        // now = old (0) + RETENTION + 1 day → t-old should be purged, t-recent kept
        let now = RETENTION_SECONDS + 86400;
        let purged = l.purge_expired(now);
        assert_eq!(purged, 1);
        assert!(l.find_by_trace_id("t-old").is_err());
        assert!(l.find_by_trace_id("t-recent").is_ok());
    }

    #[test]
    fn purge_with_no_expired_returns_zero() {
        let mut l = EvidenceLedger::default();
        l.insert(rec("t1", "op", 1_000_000_000)).unwrap();
        assert_eq!(l.purge_expired(1_000_000_001), 0);
        assert_eq!(l.record_count(), 1);
    }

    #[test]
    fn retention_is_100_days() {
        assert_eq!(RETENTION_SECONDS, 100 * 86_400);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut l = EvidenceLedger::default();
        l.schema_version = "9.9.9".into();
        assert!(matches!(
            l.validate().unwrap_err(),
            LedgerError::SchemaMismatch { .. }
        ));
    }

    #[test]
    fn ledger_serde_roundtrip() {
        let mut l = EvidenceLedger::default();
        l.insert(rec("t1", "op", 1_000_000_000)).unwrap();
        let j = serde_json::to_string(&l).unwrap();
        let back: EvidenceLedger = serde_json::from_str(&j).unwrap();
        assert_eq!(l, back);
    }
}
