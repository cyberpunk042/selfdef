//! `selfdef-host-fingerprint-attestation` — operator host attestation.
//!
//! 4-tuple: (kernel_id, cpu_id, boot_id, fs_id). Operator signs the
//! tuple at install + re-signs on legitimate hardware changes. The
//! daemon compares the live tuple at every boot.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Host fingerprint tuple.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostFingerprint {
    /// Kernel id (e.g. linux release + build id).
    pub kernel_id: String,
    /// CPU id (vendor + model + microcode rev).
    pub cpu_id: String,
    /// Boot id (changes every cold boot).
    pub boot_id: String,
    /// Filesystem id (ZFS pool guid).
    pub fs_id: String,
}

/// Operator attestation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostAttestation {
    /// Schema version.
    pub schema_version: String,
    /// Pinned fingerprint at attestation time.
    pub pinned: HostFingerprint,
    /// ISO-8601 UTC when attestation was signed.
    pub signed_at: String,
    /// Operator MS003 fingerprint.
    pub actor: String,
    /// MS003 signature over canonical-JSON of `pinned + signed_at + actor`.
    pub signature: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum AttestationError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Missing field.
    #[error("missing field: {0}")]
    MissingField(&'static str),
    /// Unsigned.
    #[error("attestation unsigned")]
    Unsigned,
    /// Mismatch on field.
    #[error("fingerprint mismatch on {field}: pinned={pinned}, live={live}")]
    Mismatch {
        /// field.
        field: &'static str,
        /// pinned.
        pinned: String,
        /// live.
        live: String,
    },
}

impl HostFingerprint {
    /// Validate non-empty.
    pub fn validate(&self) -> Result<(), AttestationError> {
        if self.kernel_id.is_empty() {
            return Err(AttestationError::MissingField("kernel_id"));
        }
        if self.cpu_id.is_empty() {
            return Err(AttestationError::MissingField("cpu_id"));
        }
        if self.boot_id.is_empty() {
            return Err(AttestationError::MissingField("boot_id"));
        }
        if self.fs_id.is_empty() {
            return Err(AttestationError::MissingField("fs_id"));
        }
        Ok(())
    }
}

impl HostAttestation {
    /// Validate the attestation shape.
    pub fn validate(&self) -> Result<(), AttestationError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(AttestationError::SchemaMismatch);
        }
        self.pinned.validate()?;
        if self.signed_at.is_empty() {
            return Err(AttestationError::MissingField("signed_at"));
        }
        if self.actor.is_empty() {
            return Err(AttestationError::MissingField("actor"));
        }
        if self.signature.is_empty() {
            return Err(AttestationError::Unsigned);
        }
        Ok(())
    }

    /// Compare pinned against a live fingerprint.
    /// Note: `boot_id` is allowed to differ since it changes every boot;
    /// other fields must match.
    pub fn assert_matches_live(&self, live: &HostFingerprint) -> Result<(), AttestationError> {
        self.validate()?;
        if self.pinned.kernel_id != live.kernel_id {
            return Err(AttestationError::Mismatch {
                field: "kernel_id",
                pinned: self.pinned.kernel_id.clone(),
                live: live.kernel_id.clone(),
            });
        }
        if self.pinned.cpu_id != live.cpu_id {
            return Err(AttestationError::Mismatch {
                field: "cpu_id",
                pinned: self.pinned.cpu_id.clone(),
                live: live.cpu_id.clone(),
            });
        }
        if self.pinned.fs_id != live.fs_id {
            return Err(AttestationError::Mismatch {
                field: "fs_id",
                pinned: self.pinned.fs_id.clone(),
                live: live.fs_id.clone(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp() -> HostFingerprint {
        HostFingerprint {
            kernel_id: "linux-6.18".into(),
            cpu_id: "amd-zen5-9900x".into(),
            boot_id: "boot-001".into(),
            fs_id: "zpool-abc".into(),
        }
    }

    fn att() -> HostAttestation {
        HostAttestation {
            schema_version: SCHEMA_VERSION.into(),
            pinned: fp(),
            signed_at: "2026-05-19T03:00:00Z".into(),
            actor: "op-fp".into(),
            signature: "sig".into(),
        }
    }

    #[test]
    fn ok_attestation_validates() {
        att().validate().unwrap();
    }

    #[test]
    fn boot_id_change_ok() {
        let a = att();
        let mut live = fp();
        live.boot_id = "boot-002".into();
        a.assert_matches_live(&live).unwrap();
    }

    #[test]
    fn kernel_change_caught() {
        let a = att();
        let mut live = fp();
        live.kernel_id = "linux-6.99".into();
        match a.assert_matches_live(&live).unwrap_err() {
            AttestationError::Mismatch { field, .. } => assert_eq!(field, "kernel_id"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn cpu_change_caught() {
        let a = att();
        let mut live = fp();
        live.cpu_id = "intel-other".into();
        match a.assert_matches_live(&live).unwrap_err() {
            AttestationError::Mismatch { field, .. } => assert_eq!(field, "cpu_id"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn fs_change_caught() {
        let a = att();
        let mut live = fp();
        live.fs_id = "different-pool".into();
        match a.assert_matches_live(&live).unwrap_err() {
            AttestationError::Mismatch { field, .. } => assert_eq!(field, "fs_id"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn unsigned_rejected() {
        let mut a = att();
        a.signature = String::new();
        assert!(matches!(
            a.validate().unwrap_err(),
            AttestationError::Unsigned
        ));
    }

    #[test]
    fn missing_kernel_id_rejected() {
        let mut a = att();
        a.pinned.kernel_id = String::new();
        assert!(matches!(
            a.validate().unwrap_err(),
            AttestationError::MissingField("kernel_id")
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut a = att();
        a.schema_version = "9.9.9".into();
        assert!(matches!(
            a.validate().unwrap_err(),
            AttestationError::SchemaMismatch
        ));
    }

    #[test]
    fn attestation_serde_roundtrip() {
        let a = att();
        let j = serde_json::to_string(&a).unwrap();
        let back: HostAttestation = serde_json::from_str(&j).unwrap();
        assert_eq!(a, back);
    }
}
