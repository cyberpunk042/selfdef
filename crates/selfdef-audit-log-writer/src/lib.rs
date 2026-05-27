//! `selfdef-audit-log-writer` — MS016 atomic-append ZFS audit log primitive.
//!
//! Per MS044 R10386-R10391 (the bug-found-and-fixed pattern from
//! guardian-core: single os.write() per record < PIPE_BUF is atomic).
//!
//! This crate exposes the typed surface + helper structures the
//! daemon's audit emitter uses; it does NOT do disk I/O itself
//! (that lives in the daemon binary so this stays no_std-friendly).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// POSIX PIPE_BUF — single writes ≤ this size are atomic on regular files
/// w.r.t. concurrent writers. Per `man 7 pipe`.
pub const PIPE_BUF_BYTES: usize = 4096;

/// Canonical mode for audit log files (0640) per MS044 R10391.
pub const AUDIT_FILE_MODE: u32 = 0o640;

/// Canonical path under sovereign-os M068 tank/vault ZFS dataset.
pub const AUDIT_LOG_PATH: &str = "/mnt/vault/context/security_audit.log";

/// Audit record envelope. Each record is one JSON line in the log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRecord {
    /// Wire schema version.
    pub schema_version: String,
    /// ISO-8601 UTC timestamp.
    pub at: String,
    /// M049 trace_id.
    pub trace_id: String,
    /// Actor MS003 fingerprint.
    pub actor: String,
    /// Event kind tag (e.g. "policy-decision", "grant-issued", "quarantine-block").
    pub kind: String,
    /// Free-form payload (operator-readable summary).
    pub summary: String,
    /// Previous record's SHA-256 hash (hex), or empty at genesis.
    pub prev_chain_hash: String,
    /// SHA-256 hash of this record body (hex).
    pub chain_hash: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum AuditWriterError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Record serialised size exceeds PIPE_BUF — non-atomic write risk.
    #[error("record size {0} bytes exceeds PIPE_BUF {PIPE_BUF_BYTES} — would not be atomic")]
    RecordTooLarge(usize),
    /// Required field empty.
    #[error("required field empty: {0}")]
    FieldEmpty(&'static str),
    /// chain_hash empty (every record must self-hash).
    #[error("chain_hash empty (every audit record must self-hash)")]
    ChainHashMissing,
}

impl AuditRecord {
    /// Validate one record + its serialised wire size against PIPE_BUF.
    pub fn validate(&self) -> Result<(), AuditWriterError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(AuditWriterError::SchemaMismatch);
        }
        if self.at.is_empty() {
            return Err(AuditWriterError::FieldEmpty("at"));
        }
        if self.trace_id.is_empty() {
            return Err(AuditWriterError::FieldEmpty("trace_id"));
        }
        if self.actor.is_empty() {
            return Err(AuditWriterError::FieldEmpty("actor"));
        }
        if self.kind.is_empty() {
            return Err(AuditWriterError::FieldEmpty("kind"));
        }
        if self.chain_hash.is_empty() {
            return Err(AuditWriterError::ChainHashMissing);
        }
        // Compute serialised size + newline.
        let json = serde_json::to_string(self).unwrap_or_default();
        let total = json.len() + 1; // +1 for trailing newline
        if total > PIPE_BUF_BYTES {
            return Err(AuditWriterError::RecordTooLarge(total));
        }
        Ok(())
    }

    /// Build a single newline-terminated buffer ready for one atomic os.write().
    /// Returns Err if the record fails validation OR its serialised size
    /// would exceed PIPE_BUF (the atomicity boundary).
    pub fn to_atomic_line(&self) -> Result<Vec<u8>, AuditWriterError> {
        self.validate()?;
        let mut buf =
            serde_json::to_vec(self).map_err(|_| AuditWriterError::FieldEmpty("serde_failed"))?;
        buf.push(b'\n');
        Ok(buf)
    }
}

/// Chain continuity verifier — given a list of records in append order,
/// returns Err at the first prev_chain_hash that does not match its
/// predecessor's chain_hash.
pub fn verify_chain_continuity(records: &[AuditRecord]) -> Result<(), AuditWriterError> {
    for (i, window) in records.windows(2).enumerate() {
        let prev = &window[0];
        let next = &window[1];
        if next.prev_chain_hash != prev.chain_hash {
            return Err(AuditWriterError::FieldEmpty(if i == 0 {
                "chain_break_at_index_1"
            } else {
                "chain_break_mid_log"
            }));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_record() -> AuditRecord {
        AuditRecord {
            schema_version: SCHEMA_VERSION.into(),
            at: "2026-05-19T03:00:00Z".into(),
            trace_id: "trace-001".into(),
            actor: "operator-fp".into(),
            kind: "policy-decision".into(),
            summary: "fs.write allowed".into(),
            prev_chain_hash: "0x00".into(),
            chain_hash: "0xaa".into(),
        }
    }

    #[test]
    fn ok_record_validates() {
        ok_record().validate().unwrap();
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = ok_record();
        r.schema_version = "9.9.9".into();
        assert!(matches!(
            r.validate().unwrap_err(),
            AuditWriterError::SchemaMismatch
        ));
    }

    #[test]
    fn empty_at_rejected() {
        let mut r = ok_record();
        r.at = String::new();
        assert!(matches!(
            r.validate().unwrap_err(),
            AuditWriterError::FieldEmpty("at")
        ));
    }

    #[test]
    fn empty_trace_rejected() {
        let mut r = ok_record();
        r.trace_id = String::new();
        assert!(matches!(
            r.validate().unwrap_err(),
            AuditWriterError::FieldEmpty("trace_id")
        ));
    }

    #[test]
    fn empty_actor_rejected() {
        let mut r = ok_record();
        r.actor = String::new();
        assert!(matches!(
            r.validate().unwrap_err(),
            AuditWriterError::FieldEmpty("actor")
        ));
    }

    #[test]
    fn empty_kind_rejected() {
        let mut r = ok_record();
        r.kind = String::new();
        assert!(matches!(
            r.validate().unwrap_err(),
            AuditWriterError::FieldEmpty("kind")
        ));
    }

    #[test]
    fn empty_chain_hash_rejected() {
        let mut r = ok_record();
        r.chain_hash = String::new();
        assert!(matches!(
            r.validate().unwrap_err(),
            AuditWriterError::ChainHashMissing
        ));
    }

    #[test]
    fn oversized_record_rejected() {
        let mut r = ok_record();
        r.summary = "x".repeat(5000); // pushes total > PIPE_BUF
        assert!(matches!(
            r.validate().unwrap_err(),
            AuditWriterError::RecordTooLarge(_)
        ));
    }

    #[test]
    fn to_atomic_line_terminates_with_newline() {
        let r = ok_record();
        let bytes = r.to_atomic_line().unwrap();
        assert!(bytes.ends_with(b"\n"));
        assert!(bytes.len() <= PIPE_BUF_BYTES);
    }

    #[test]
    fn to_atomic_line_fails_oversized() {
        let mut r = ok_record();
        r.summary = "x".repeat(5000);
        assert!(r.to_atomic_line().is_err());
    }

    #[test]
    fn chain_continuity_passes_linked() {
        let mut r1 = ok_record();
        r1.chain_hash = "0xaa".into();
        let mut r2 = ok_record();
        r2.prev_chain_hash = "0xaa".into();
        r2.chain_hash = "0xbb".into();
        let mut r3 = ok_record();
        r3.prev_chain_hash = "0xbb".into();
        r3.chain_hash = "0xcc".into();
        verify_chain_continuity(&[r1, r2, r3]).unwrap();
    }

    #[test]
    fn chain_continuity_detects_break() {
        let mut r1 = ok_record();
        r1.chain_hash = "0xaa".into();
        let mut r2 = ok_record();
        r2.prev_chain_hash = "WRONG".into();
        r2.chain_hash = "0xbb".into();
        assert!(verify_chain_continuity(&[r1, r2]).is_err());
    }

    #[test]
    fn pipe_buf_is_4096() {
        assert_eq!(PIPE_BUF_BYTES, 4096);
    }

    #[test]
    fn audit_file_mode_is_0640() {
        assert_eq!(AUDIT_FILE_MODE, 0o640);
    }

    #[test]
    fn record_serde_roundtrip() {
        let r = ok_record();
        let j = serde_json::to_string(&r).unwrap();
        let back: AuditRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
