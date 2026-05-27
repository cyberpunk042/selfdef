//! `selfdef-policy-state-snapshot` — backup envelope.
//!
//! Wraps a policy blob with metadata + FNV-1a digest. verify_digest
//! recomputes against the blob and reports drift.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Snapshot envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyStateSnapshot {
    /// Schema version.
    pub schema_version: String,
    /// Engine version at snapshot time.
    pub engine_version: String,
    /// Snapshot time (unix seconds).
    pub snapshot_at_unix: u64,
    /// Opaque blob (JSON, etc.).
    pub policy_blob: String,
    /// FNV-1a u64 hex digest of policy_blob.
    pub digest_hex: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SnapshotError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty version.
    #[error("engine_version empty")]
    EmptyEngineVersion,
    /// Empty blob.
    #[error("policy_blob empty")]
    EmptyPolicyBlob,
    /// Digest mismatch.
    #[error("digest_hex {got} != expected {expected}")]
    DigestMismatch {
        /// got.
        got: String,
        /// expected.
        expected: String,
    },
    /// Malformed digest.
    #[error("digest_hex not 16-char lowercase hex")]
    BadDigestFormat,
}

impl PolicyStateSnapshot {
    /// Build a fresh snapshot computing the digest.
    pub fn build(
        engine_version: &str,
        snapshot_at_unix: u64,
        policy_blob: &str,
    ) -> Result<Self, SnapshotError> {
        if engine_version.is_empty() {
            return Err(SnapshotError::EmptyEngineVersion);
        }
        if policy_blob.is_empty() {
            return Err(SnapshotError::EmptyPolicyBlob);
        }
        let digest_hex = format!("{:016x}", fnv1a_64(policy_blob.as_bytes()));
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            engine_version: engine_version.into(),
            snapshot_at_unix,
            policy_blob: policy_blob.into(),
            digest_hex,
        })
    }

    /// Recompute digest from blob and verify.
    pub fn verify_digest(&self) -> Result<(), SnapshotError> {
        if !valid_hex(&self.digest_hex) {
            return Err(SnapshotError::BadDigestFormat);
        }
        let expected = format!("{:016x}", fnv1a_64(self.policy_blob.as_bytes()));
        if expected != self.digest_hex {
            return Err(SnapshotError::DigestMismatch {
                got: self.digest_hex.clone(),
                expected,
            });
        }
        Ok(())
    }

    /// Validate envelope shape + digest.
    pub fn validate(&self) -> Result<(), SnapshotError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SnapshotError::SchemaMismatch);
        }
        if self.engine_version.is_empty() {
            return Err(SnapshotError::EmptyEngineVersion);
        }
        if self.policy_blob.is_empty() {
            return Err(SnapshotError::EmptyPolicyBlob);
        }
        self.verify_digest()
    }
}

fn fnv1a_64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn valid_hex(s: &str) -> bool {
    s.len() == 16
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_verify_ok() {
        let s = PolicyStateSnapshot::build("1.0.0", 1000, "{\"x\":1}").unwrap();
        s.verify_digest().unwrap();
    }

    #[test]
    fn tampered_blob_detected() {
        let mut s = PolicyStateSnapshot::build("1.0.0", 1000, "{\"x\":1}").unwrap();
        s.policy_blob = "{\"x\":2}".into();
        assert!(matches!(
            s.verify_digest().unwrap_err(),
            SnapshotError::DigestMismatch { .. }
        ));
    }

    #[test]
    fn empty_engine_rejected() {
        assert!(matches!(
            PolicyStateSnapshot::build("", 0, "blob").unwrap_err(),
            SnapshotError::EmptyEngineVersion
        ));
    }

    #[test]
    fn empty_blob_rejected() {
        assert!(matches!(
            PolicyStateSnapshot::build("1.0", 0, "").unwrap_err(),
            SnapshotError::EmptyPolicyBlob
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = PolicyStateSnapshot::build("1.0.0", 0, "blob").unwrap();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            SnapshotError::SchemaMismatch
        ));
    }

    #[test]
    fn bad_digest_format_rejected() {
        let mut s = PolicyStateSnapshot::build("1.0.0", 0, "blob").unwrap();
        s.digest_hex = "TOOSHORT".into();
        assert!(matches!(
            s.verify_digest().unwrap_err(),
            SnapshotError::BadDigestFormat
        ));
    }

    #[test]
    fn uppercase_hex_rejected() {
        let mut s = PolicyStateSnapshot::build("1.0.0", 0, "blob").unwrap();
        s.digest_hex = s.digest_hex.to_uppercase();
        assert!(matches!(
            s.verify_digest().unwrap_err(),
            SnapshotError::BadDigestFormat
        ));
    }

    #[test]
    fn snapshot_serde_roundtrip() {
        let s = PolicyStateSnapshot::build("1.0.0", 1000, "blob").unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: PolicyStateSnapshot = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
