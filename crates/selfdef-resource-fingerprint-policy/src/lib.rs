//! `selfdef-resource-fingerprint-policy` — resource-pinning gate.
//!
//! Each pinned resource has (id, expected_digest). verify(id,
//! observed_bytes) computes FNV-1a and compares; mismatch surfaces
//! Drift with expected vs observed hex.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One pin.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourcePin {
    /// Stable id.
    pub id: String,
    /// Expected FNV-1a u64 hex.
    pub expected_hex: String,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceFingerprintPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Pins.
    pub pins: Vec<ResourcePin>,
}

/// Verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum VerifyResult {
    /// Match.
    Ok,
    /// Drift.
    Drift {
        /// expected hex.
        expected: String,
        /// observed hex.
        observed: String,
    },
    /// Unknown resource id.
    Unknown,
}

/// Errors.
#[derive(Debug, Error)]
pub enum FpError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("pin id empty")]
    EmptyId,
    /// Bad expected hex.
    #[error("pin {0} expected_hex not 16-char hex")]
    BadExpectedHex(String),
    /// Duplicate id.
    #[error("duplicate pin id: {0}")]
    DuplicateId(String),
}

impl ResourceFingerprintPolicy {
    /// New empty.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            pins: Vec::new(),
        }
    }

    /// Pin a resource.
    pub fn pin(&mut self, id: &str, expected_hex: &str) -> Result<(), FpError> {
        if id.is_empty() {
            return Err(FpError::EmptyId);
        }
        if !valid_hex(expected_hex) {
            return Err(FpError::BadExpectedHex(id.into()));
        }
        if self.pins.iter().any(|p| p.id == id) {
            return Err(FpError::DuplicateId(id.into()));
        }
        self.pins.push(ResourcePin {
            id: id.into(),
            expected_hex: expected_hex.to_lowercase(),
        });
        Ok(())
    }

    /// Verify.
    pub fn verify(&self, id: &str, observed_bytes: &[u8]) -> VerifyResult {
        let pin = match self.pins.iter().find(|p| p.id == id) {
            Some(p) => p,
            None => return VerifyResult::Unknown,
        };
        let observed_hex = format!("{:016x}", fnv1a_64(observed_bytes));
        if observed_hex == pin.expected_hex {
            VerifyResult::Ok
        } else {
            VerifyResult::Drift {
                expected: pin.expected_hex.clone(),
                observed: observed_hex,
            }
        }
    }

    /// Compute the hex of supplied bytes (helper for callers).
    pub fn compute_hex(bytes: &[u8]) -> String {
        format!("{:016x}", fnv1a_64(bytes))
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), FpError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(FpError::SchemaMismatch);
        }
        use std::collections::HashSet;
        let mut seen: HashSet<&str> = HashSet::new();
        for p in &self.pins {
            if p.id.is_empty() {
                return Err(FpError::EmptyId);
            }
            if !valid_hex(&p.expected_hex) {
                return Err(FpError::BadExpectedHex(p.id.clone()));
            }
            if !seen.insert(p.id.as_str()) {
                return Err(FpError::DuplicateId(p.id.clone()));
            }
        }
        Ok(())
    }
}

fn valid_hex(s: &str) -> bool {
    s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn fnv1a_64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

impl Default for ResourceFingerprintPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_and_verify_ok() {
        let bytes = b"hello world";
        let hex = ResourceFingerprintPolicy::compute_hex(bytes);
        let mut p = ResourceFingerprintPolicy::new();
        p.pin("greeting", &hex).unwrap();
        assert!(matches!(p.verify("greeting", bytes), VerifyResult::Ok));
    }

    #[test]
    fn drift_detected() {
        let mut p = ResourceFingerprintPolicy::new();
        let hex = ResourceFingerprintPolicy::compute_hex(b"original");
        p.pin("doc", &hex).unwrap();
        let result = p.verify("doc", b"tampered");
        assert!(matches!(result, VerifyResult::Drift { .. }));
    }

    #[test]
    fn unknown_returns_unknown() {
        let p = ResourceFingerprintPolicy::new();
        assert!(matches!(p.verify("ghost", b"x"), VerifyResult::Unknown));
    }

    #[test]
    fn duplicate_pin_rejected() {
        let mut p = ResourceFingerprintPolicy::new();
        let hex = ResourceFingerprintPolicy::compute_hex(b"x");
        p.pin("a", &hex).unwrap();
        assert!(matches!(
            p.pin("a", &hex).unwrap_err(),
            FpError::DuplicateId(_)
        ));
    }

    #[test]
    fn empty_id_rejected() {
        let mut p = ResourceFingerprintPolicy::new();
        let hex = ResourceFingerprintPolicy::compute_hex(b"x");
        assert!(matches!(p.pin("", &hex).unwrap_err(), FpError::EmptyId));
    }

    #[test]
    fn bad_hex_rejected() {
        let mut p = ResourceFingerprintPolicy::new();
        assert!(matches!(
            p.pin("a", "notlonghex").unwrap_err(),
            FpError::BadExpectedHex(_)
        ));
        assert!(matches!(
            p.pin("a", "ZZZZZZZZZZZZZZZZ").unwrap_err(),
            FpError::BadExpectedHex(_)
        ));
    }

    #[test]
    fn case_insensitive_storage() {
        let mut p = ResourceFingerprintPolicy::new();
        let hex_upper = ResourceFingerprintPolicy::compute_hex(b"x").to_uppercase();
        p.pin("a", &hex_upper).unwrap();
        // verify still ok with the same content.
        assert!(matches!(p.verify("a", b"x"), VerifyResult::Ok));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = ResourceFingerprintPolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), FpError::SchemaMismatch));
    }

    #[test]
    fn result_serde_kebab() {
        let d = VerifyResult::Drift {
            expected: "x".into(),
            observed: "y".into(),
        };
        assert!(
            serde_json::to_string(&d)
                .unwrap()
                .contains("\"kind\":\"drift\"")
        );
    }

    #[test]
    fn policy_serde_roundtrip() {
        let mut p = ResourceFingerprintPolicy::new();
        let hex = ResourceFingerprintPolicy::compute_hex(b"x");
        p.pin("a", &hex).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: ResourceFingerprintPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
