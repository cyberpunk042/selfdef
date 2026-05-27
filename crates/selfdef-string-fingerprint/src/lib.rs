//! `selfdef-string-fingerprint` — short stable hex fingerprint.
//!
//! fingerprint(s) → 16-hex-char string from FNV-1a-64. short(s,
//! len) returns the leading `len` chars (1..=16). Deterministic;
//! same input always produces same output.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Errors.
#[derive(Debug, Error)]
pub enum FpError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Bad len.
    #[error("len must be 1..=16")]
    BadLen,
}

/// Versioned state placeholder.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FingerprintState {
    /// Schema version.
    pub schema_version: String,
    /// Last computed fingerprint.
    pub last: Option<String>,
}

/// Compute FNV-1a-64 fingerprint as 16 hex chars.
pub fn fingerprint(s: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

/// Shortened to leading `len` chars (1..=16).
pub fn short(s: &str, len: usize) -> Result<String, FpError> {
    if len == 0 || len > 16 {
        return Err(FpError::BadLen);
    }
    Ok(fingerprint(s)[..len].to_string())
}

impl FingerprintState {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            last: None,
        }
    }

    /// Compute + store.
    pub fn compute_and_store(&mut self, s: &str) -> &str {
        let fp = fingerprint(s);
        self.last = Some(fp);
        self.last.as_deref().unwrap()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), FpError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(FpError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for FingerprintState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let a = fingerprint("hello world");
        let b = fingerprint("hello world");
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn different_inputs_differ() {
        assert_ne!(fingerprint("a"), fingerprint("b"));
    }

    #[test]
    fn fnv1a_known_value() {
        // FNV-1a-64("") = 0xcbf29ce484222325.
        assert_eq!(fingerprint(""), "cbf29ce484222325");
    }

    #[test]
    fn fnv1a_foobar() {
        // FNV-1a-64("foobar") = 0x85944171f73967e8.
        assert_eq!(fingerprint("foobar"), "85944171f73967e8");
    }

    #[test]
    fn short_truncates() {
        let s = short("hello world", 8).unwrap();
        assert_eq!(s.len(), 8);
        assert!(fingerprint("hello world").starts_with(&s));
    }

    #[test]
    fn short_bad_len() {
        assert!(matches!(short("x", 0).unwrap_err(), FpError::BadLen));
        assert!(matches!(short("x", 17).unwrap_err(), FpError::BadLen));
    }

    #[test]
    fn state_stores() {
        let mut s = FingerprintState::new();
        s.compute_and_store("k");
        assert_eq!(s.last.as_deref(), Some(fingerprint("k").as_str()));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = FingerprintState::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), FpError::SchemaMismatch));
    }

    #[test]
    fn state_serde_roundtrip() {
        let mut s = FingerprintState::new();
        s.compute_and_store("hi");
        let j = serde_json::to_string(&s).unwrap();
        let back: FingerprintState = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
