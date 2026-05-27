//! `selfdef-policy-cache-key` — composite cache key.
//!
//! key(policy_version, input) builds a stable string of the
//! shape "<version>:<16-hex>" where 16-hex is FNV-1a-64 of
//! input bytes. Two calls with same inputs produce identical
//! keys.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Versioned state placeholder.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyCacheKeyState {
    /// Schema version.
    pub schema_version: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum KeyError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("policy_version empty")]
    EmptyVersion,
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Build composite key.
pub fn key(policy_version: &str, input: &[u8]) -> Result<String, KeyError> {
    if policy_version.is_empty() {
        return Err(KeyError::EmptyVersion);
    }
    let h = fnv1a_64(input);
    Ok(format!("{}:{:016x}", policy_version, h))
}

impl PolicyCacheKeyState {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), KeyError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(KeyError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for PolicyCacheKeyState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let a = key("1.0", b"hello world").unwrap();
        let b = key("1.0", b"hello world").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_versions_diverge() {
        let a = key("1.0", b"x").unwrap();
        let b = key("2.0", b"x").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_inputs_diverge() {
        let a = key("1.0", b"x").unwrap();
        let b = key("1.0", b"y").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn empty_input_ok() {
        let k = key("1.0", b"").unwrap();
        // FNV-1a-64("") = cbf29ce484222325
        assert_eq!(k, "1.0:cbf29ce484222325");
    }

    #[test]
    fn empty_version_rejected() {
        assert!(matches!(key("", b"x").unwrap_err(), KeyError::EmptyVersion));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = PolicyCacheKeyState::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            KeyError::SchemaMismatch
        ));
    }

    #[test]
    fn state_serde_roundtrip() {
        let s = PolicyCacheKeyState::new();
        let j = serde_json::to_string(&s).unwrap();
        let back: PolicyCacheKeyState = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
