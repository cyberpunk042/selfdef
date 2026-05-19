//! `selfdef-grant-receipt` — operator-signed grant ack.
//!
//! Daemon returns a `GrantReceipt` whenever a grant is issued. Carries
//! `scope_hash` (FNV-1a of canonical scope string) rather than raw
//! scope to avoid leaking secrets in the receipt itself.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_grants_mirror::GrantKind;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// FNV-1a 64-bit.
pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// One grant receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantReceipt {
    /// Schema version.
    pub schema_version: String,
    /// Grant id (ULID).
    pub grant_id: String,
    /// Grant kind.
    pub kind: GrantKind,
    /// FNV-1a hex of canonical scope.
    pub scope_hash: String,
    /// ISO-8601 UTC issued_at.
    pub issued_at: String,
    /// ISO-8601 UTC expires_at.
    pub expires_at: String,
    /// MS003 signature.
    pub signature: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ReceiptError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Missing field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    /// expires <= issued.
    #[error("expires_at {expires_at} <= issued_at {issued_at}")]
    BadWindow {
        /// issued_at.
        issued_at: String,
        /// expires_at.
        expires_at: String,
    },
    /// scope_hash mismatch.
    #[error("scope_hash mismatch: receipt={receipt} computed={computed}")]
    ScopeHashMismatch {
        /// receipt.
        receipt: String,
        /// computed.
        computed: String,
    },
}

/// Compute the canonical scope hash hex string.
pub fn scope_hash(scope: &str) -> String {
    format!("0x{:016x}", fnv1a_64(scope.as_bytes()))
}

impl GrantReceipt {
    /// Validate field shape.
    pub fn validate(&self) -> Result<(), ReceiptError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ReceiptError::SchemaMismatch);
        }
        if self.grant_id.is_empty() { return Err(ReceiptError::MissingField("grant_id")); }
        if self.scope_hash.is_empty() { return Err(ReceiptError::MissingField("scope_hash")); }
        if self.issued_at.is_empty() { return Err(ReceiptError::MissingField("issued_at")); }
        if self.expires_at.is_empty() { return Err(ReceiptError::MissingField("expires_at")); }
        if self.signature.is_empty() { return Err(ReceiptError::MissingField("signature")); }
        if self.expires_at <= self.issued_at {
            return Err(ReceiptError::BadWindow {
                issued_at: self.issued_at.clone(),
                expires_at: self.expires_at.clone(),
            });
        }
        Ok(())
    }

    /// Compare receipt scope_hash against a fresh scope string.
    pub fn verify_scope(&self, scope: &str) -> Result<(), ReceiptError> {
        let computed = scope_hash(scope);
        if self.scope_hash != computed {
            return Err(ReceiptError::ScopeHashMismatch {
                receipt: self.scope_hash.clone(),
                computed,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(scope: &str) -> GrantReceipt {
        GrantReceipt {
            schema_version: SCHEMA_VERSION.into(),
            grant_id: "g-001".into(),
            kind: GrantKind::Filesystem,
            scope_hash: scope_hash(scope),
            issued_at: "2026-05-19T03:00:00Z".into(),
            expires_at: "2026-05-19T04:00:00Z".into(),
            signature: "ms003-sig".into(),
        }
    }

    #[test]
    fn scope_hash_deterministic() {
        assert_eq!(scope_hash("/x"), scope_hash("/x"));
    }

    #[test]
    fn scope_hash_format() {
        let h = scope_hash("/x");
        assert!(h.starts_with("0x"));
        assert_eq!(h.len(), 2 + 16);
    }

    #[test]
    fn ok_receipt_validates() {
        r("/x").validate().unwrap();
    }

    #[test]
    fn missing_grant_id_caught() {
        let mut x = r("/x");
        x.grant_id = String::new();
        assert!(matches!(x.validate().unwrap_err(), ReceiptError::MissingField("grant_id")));
    }

    #[test]
    fn bad_window_caught() {
        let mut x = r("/x");
        x.expires_at = "2026-05-19T02:00:00Z".into();
        assert!(matches!(x.validate().unwrap_err(), ReceiptError::BadWindow { .. }));
    }

    #[test]
    fn verify_scope_passes_on_match() {
        r("/workspace/x").verify_scope("/workspace/x").unwrap();
    }

    #[test]
    fn verify_scope_fails_on_mismatch() {
        let receipt = r("/workspace/x");
        assert!(matches!(receipt.verify_scope("/workspace/y").unwrap_err(),
            ReceiptError::ScopeHashMismatch { .. }));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut x = r("/x");
        x.schema_version = "9.9.9".into();
        assert!(matches!(x.validate().unwrap_err(), ReceiptError::SchemaMismatch));
    }

    #[test]
    fn receipt_serde_roundtrip() {
        let x = r("/x");
        let j = serde_json::to_string(&x).unwrap();
        let back: GrantReceipt = serde_json::from_str(&j).unwrap();
        assert_eq!(x, back);
    }
}
