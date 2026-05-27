//! `selfdef-cert-pin-set` — per-host cert fingerprint pin store.
//!
//! For each host, a set of accepted SHA-256 fingerprints (hex)
//! each with its own expires_at_ms (0 = permanent). pin(host, fp,
//! now, ttl) adds; matches(host, fp, now) true iff any
//! non-expired pin equals fp. Multiple pins per host enable
//! overlap during rotation.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertPinSet {
    /// Schema version.
    pub schema_version: String,
    /// host → (fingerprint → expires_at_ms).
    pub pins: BTreeMap<String, BTreeMap<String, u64>>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum PinError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("host empty")]
    EmptyHost,
    /// Empty.
    #[error("fingerprint empty")]
    EmptyFp,
    /// Bad fp.
    #[error("fingerprint must be 64 hex chars (SHA-256)")]
    BadFp,
    /// Unknown host.
    #[error("unknown host: {0}")]
    UnknownHost(String),
}

fn is_valid_fp(fp: &str) -> bool {
    fp.len() == 64 && fp.bytes().all(|b| b.is_ascii_hexdigit())
}

impl CertPinSet {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            pins: BTreeMap::new(),
        }
    }

    /// Pin a fingerprint for host (ttl=0 → permanent).
    pub fn pin(&mut self, host: &str, fp: &str, now_ms: u64, ttl_ms: u64) -> Result<(), PinError> {
        if host.is_empty() {
            return Err(PinError::EmptyHost);
        }
        if fp.is_empty() {
            return Err(PinError::EmptyFp);
        }
        if !is_valid_fp(fp) {
            return Err(PinError::BadFp);
        }
        let exp = if ttl_ms == 0 {
            0
        } else {
            now_ms.saturating_add(ttl_ms)
        };
        self.pins
            .entry(host.into())
            .or_default()
            .insert(fp.to_ascii_lowercase(), exp);
        Ok(())
    }

    /// Unpin a specific fingerprint.
    pub fn unpin(&mut self, host: &str, fp: &str) -> Result<(), PinError> {
        let host_pins = self
            .pins
            .get_mut(host)
            .ok_or_else(|| PinError::UnknownHost(host.into()))?;
        host_pins.remove(&fp.to_ascii_lowercase());
        if host_pins.is_empty() {
            self.pins.remove(host);
        }
        Ok(())
    }

    /// Does fp match any non-expired pin for host?
    pub fn matches(&self, host: &str, fp: &str, now_ms: u64) -> bool {
        let host_pins = match self.pins.get(host) {
            Some(p) => p,
            None => return false,
        };
        let fp_lc = fp.to_ascii_lowercase();
        match host_pins.get(&fp_lc) {
            Some(&exp) => exp == 0 || exp > now_ms,
            None => false,
        }
    }

    /// Prune expired pins.
    pub fn compact(&mut self, now_ms: u64) {
        for v in self.pins.values_mut() {
            v.retain(|_, &mut exp| exp == 0 || exp > now_ms);
        }
        self.pins.retain(|_, v| !v.is_empty());
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), PinError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(PinError::SchemaMismatch);
        }
        for (h, fps) in &self.pins {
            if h.is_empty() {
                return Err(PinError::EmptyHost);
            }
            for f in fps.keys() {
                if !is_valid_fp(f) {
                    return Err(PinError::BadFp);
                }
            }
        }
        Ok(())
    }
}

impl Default for CertPinSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FP_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn pin_then_match() {
        let mut s = CertPinSet::new();
        s.pin("example.com", FP_A, 0, 1000).unwrap();
        assert!(s.matches("example.com", FP_A, 500));
        assert!(!s.matches("example.com", FP_B, 500));
    }

    #[test]
    fn case_insensitive_fp() {
        let mut s = CertPinSet::new();
        s.pin("h", FP_A, 0, 0).unwrap();
        let upper: String = FP_A.chars().map(|c| c.to_ascii_uppercase()).collect();
        assert!(s.matches("h", &upper, 0));
    }

    #[test]
    fn expires_after_ttl() {
        let mut s = CertPinSet::new();
        s.pin("h", FP_A, 0, 1000).unwrap();
        assert!(!s.matches("h", FP_A, 2000));
    }

    #[test]
    fn multiple_pins_overlap() {
        let mut s = CertPinSet::new();
        s.pin("h", FP_A, 0, 0).unwrap();
        s.pin("h", FP_B, 0, 0).unwrap();
        assert!(s.matches("h", FP_A, 100));
        assert!(s.matches("h", FP_B, 100));
    }

    #[test]
    fn unpin_removes_specific() {
        let mut s = CertPinSet::new();
        s.pin("h", FP_A, 0, 0).unwrap();
        s.pin("h", FP_B, 0, 0).unwrap();
        s.unpin("h", FP_A).unwrap();
        assert!(!s.matches("h", FP_A, 0));
        assert!(s.matches("h", FP_B, 0));
    }

    #[test]
    fn bad_fp_rejected() {
        let mut s = CertPinSet::new();
        assert!(matches!(
            s.pin("h", "short", 0, 0).unwrap_err(),
            PinError::BadFp
        ));
        assert!(matches!(
            s.pin("h", "", 0, 0).unwrap_err(),
            PinError::EmptyFp
        ));
        assert!(matches!(
            s.pin("", FP_A, 0, 0).unwrap_err(),
            PinError::EmptyHost
        ));
    }

    #[test]
    fn compact_prunes() {
        let mut s = CertPinSet::new();
        s.pin("h", FP_A, 0, 1000).unwrap();
        s.compact(2000);
        assert!(s.pins.is_empty());
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = CertPinSet::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            PinError::SchemaMismatch
        ));
    }

    #[test]
    fn cert_pin_serde_roundtrip() {
        let mut s = CertPinSet::new();
        s.pin("h", FP_A, 0, 0).unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: CertPinSet = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
