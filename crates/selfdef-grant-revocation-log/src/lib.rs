//! `selfdef-grant-revocation-log` — append-only grant revocation audit log.
//!
//! Each entry records: grant_id (links to selfdef-grants-mirror), kind,
//! revocation reason (5 canonical reasons), revoking actor's MS003
//! signature, ISO-8601 UTC timestamp, originating trace_id, and a
//! one-line operator-readable note.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_grants_mirror::GrantKind;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// 5 canonical revocation reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RevocationReason {
    /// Operator explicitly revoked via CLI.
    OperatorForced,
    /// Mirror-vs-source drift detected (MS042).
    DriftDetected,
    /// TTL cut short by policy gate.
    TtlCut,
    /// Anomaly engine flagged the grant.
    AnomalyTriggered,
    /// Superseded by a newer grant with different scope.
    Superseded,
}

/// One revocation entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationEntry {
    /// Grant id (matches selfdef-grants-mirror's grant_id).
    pub grant_id: String,
    /// Grant kind.
    pub kind: GrantKind,
    /// Reason.
    pub reason: RevocationReason,
    /// Revoking actor's MS003 fingerprint (non-empty).
    pub actor: String,
    /// ISO-8601 UTC.
    pub revoked_at: String,
    /// M049 trace_id linking to the originating decision (non-empty).
    pub trace_id: String,
    /// Operator-readable note.
    pub note: String,
}

/// Log envelope (append-only in practice).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationLog {
    /// Schema version.
    pub schema_version: String,
    /// Entries.
    pub entries: Vec<RevocationEntry>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RevocationError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty grant_id.
    #[error("entry {idx}: grant_id missing")]
    MissingGrantId {
        /// Index.
        idx: usize,
    },
    /// Empty actor.
    #[error("entry {idx}: actor missing")]
    MissingActor {
        /// Index.
        idx: usize,
    },
    /// Empty timestamp.
    #[error("entry {idx}: revoked_at missing")]
    MissingTimestamp {
        /// Index.
        idx: usize,
    },
    /// Empty trace_id.
    #[error("entry {idx}: trace_id missing")]
    MissingTraceId {
        /// Index.
        idx: usize,
    },
    /// Duplicate revocation of the same grant_id.
    #[error("grant {0} revoked more than once")]
    DuplicateGrant(String),
}

impl RevocationLog {
    /// New empty log.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            entries: Vec::new(),
        }
    }

    /// Append a revocation entry.
    /// Errors if grant_id was already revoked in this log.
    pub fn revoke(&mut self, entry: RevocationEntry) -> Result<(), RevocationError> {
        if self.entries.iter().any(|e| e.grant_id == entry.grant_id) {
            return Err(RevocationError::DuplicateGrant(entry.grant_id));
        }
        self.entries.push(entry);
        Ok(())
    }

    /// True if a grant_id has a revocation in the log.
    pub fn is_revoked(&self, grant_id: &str) -> bool {
        self.entries.iter().any(|e| e.grant_id == grant_id)
    }

    /// Count entries with a given reason.
    pub fn count_by_reason(&self, reason: RevocationReason) -> usize {
        self.entries.iter().filter(|e| e.reason == reason).count()
    }

    /// Validate the log.
    pub fn validate(&self) -> Result<(), RevocationError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RevocationError::SchemaMismatch);
        }
        use std::collections::HashSet;
        let mut seen: HashSet<&str> = HashSet::new();
        for (idx, e) in self.entries.iter().enumerate() {
            if e.grant_id.is_empty() { return Err(RevocationError::MissingGrantId { idx }); }
            if e.actor.is_empty() { return Err(RevocationError::MissingActor { idx }); }
            if e.revoked_at.is_empty() { return Err(RevocationError::MissingTimestamp { idx }); }
            if e.trace_id.is_empty() { return Err(RevocationError::MissingTraceId { idx }); }
            if !seen.insert(e.grant_id.as_str()) {
                return Err(RevocationError::DuplicateGrant(e.grant_id.clone()));
            }
        }
        Ok(())
    }
}

impl Default for RevocationLog {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(grant_id: &str, kind: GrantKind, reason: RevocationReason) -> RevocationEntry {
        RevocationEntry {
            grant_id: grant_id.into(),
            kind,
            reason,
            actor: "operator-fp".into(),
            revoked_at: "2026-05-19T03:00:00Z".into(),
            trace_id: "tr-1".into(),
            note: "test".into(),
        }
    }

    #[test]
    fn empty_log_validates() {
        RevocationLog::new().validate().unwrap();
    }

    #[test]
    fn revoke_and_lookup() {
        let mut log = RevocationLog::new();
        log.revoke(entry("g1", GrantKind::Filesystem, RevocationReason::OperatorForced)).unwrap();
        assert!(log.is_revoked("g1"));
        assert!(!log.is_revoked("g2"));
        log.validate().unwrap();
    }

    #[test]
    fn duplicate_revocation_rejected() {
        let mut log = RevocationLog::new();
        log.revoke(entry("g1", GrantKind::Filesystem, RevocationReason::OperatorForced)).unwrap();
        let err = log.revoke(entry("g1", GrantKind::Filesystem, RevocationReason::DriftDetected)).unwrap_err();
        assert!(matches!(err, RevocationError::DuplicateGrant(ref id) if id == "g1"));
    }

    #[test]
    fn count_by_reason() {
        let mut log = RevocationLog::new();
        log.revoke(entry("g1", GrantKind::Filesystem, RevocationReason::OperatorForced)).unwrap();
        log.revoke(entry("g2", GrantKind::Network, RevocationReason::OperatorForced)).unwrap();
        log.revoke(entry("g3", GrantKind::Capability, RevocationReason::DriftDetected)).unwrap();
        assert_eq!(log.count_by_reason(RevocationReason::OperatorForced), 2);
        assert_eq!(log.count_by_reason(RevocationReason::DriftDetected), 1);
        assert_eq!(log.count_by_reason(RevocationReason::Superseded), 0);
    }

    #[test]
    fn missing_grant_id_caught() {
        let mut log = RevocationLog::new();
        log.entries.push(RevocationEntry {
            grant_id: String::new(),
            kind: GrantKind::Filesystem,
            reason: RevocationReason::OperatorForced,
            actor: "op".into(),
            revoked_at: "t".into(),
            trace_id: "tr".into(),
            note: String::new(),
        });
        assert!(matches!(log.validate().unwrap_err(), RevocationError::MissingGrantId { idx: 0 }));
    }

    #[test]
    fn missing_actor_caught() {
        let mut log = RevocationLog::new();
        let mut e = entry("g1", GrantKind::Filesystem, RevocationReason::OperatorForced);
        e.actor = String::new();
        log.entries.push(e);
        assert!(matches!(log.validate().unwrap_err(), RevocationError::MissingActor { idx: 0 }));
    }

    #[test]
    fn missing_timestamp_caught() {
        let mut log = RevocationLog::new();
        let mut e = entry("g1", GrantKind::Filesystem, RevocationReason::OperatorForced);
        e.revoked_at = String::new();
        log.entries.push(e);
        assert!(matches!(log.validate().unwrap_err(), RevocationError::MissingTimestamp { idx: 0 }));
    }

    #[test]
    fn missing_trace_id_caught() {
        let mut log = RevocationLog::new();
        let mut e = entry("g1", GrantKind::Filesystem, RevocationReason::OperatorForced);
        e.trace_id = String::new();
        log.entries.push(e);
        assert!(matches!(log.validate().unwrap_err(), RevocationError::MissingTraceId { idx: 0 }));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut log = RevocationLog::new();
        log.schema_version = "9.9.9".into();
        assert!(matches!(log.validate().unwrap_err(), RevocationError::SchemaMismatch));
    }

    #[test]
    fn reason_serde_kebab() {
        assert_eq!(serde_json::to_string(&RevocationReason::OperatorForced).unwrap(), "\"operator-forced\"");
        assert_eq!(serde_json::to_string(&RevocationReason::DriftDetected).unwrap(), "\"drift-detected\"");
        assert_eq!(serde_json::to_string(&RevocationReason::TtlCut).unwrap(), "\"ttl-cut\"");
        assert_eq!(serde_json::to_string(&RevocationReason::AnomalyTriggered).unwrap(), "\"anomaly-triggered\"");
        assert_eq!(serde_json::to_string(&RevocationReason::Superseded).unwrap(), "\"superseded\"");
    }

    #[test]
    fn log_serde_roundtrip() {
        let mut log = RevocationLog::new();
        log.revoke(entry("g1", GrantKind::Filesystem, RevocationReason::OperatorForced)).unwrap();
        log.revoke(entry("g2", GrantKind::Network, RevocationReason::DriftDetected)).unwrap();
        let j = serde_json::to_string(&log).unwrap();
        let back: RevocationLog = serde_json::from_str(&j).unwrap();
        assert_eq!(log, back);
    }
}
