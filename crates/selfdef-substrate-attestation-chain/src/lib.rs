//! `selfdef-substrate-attestation-chain` — chained substrate attestations.
//!
//! Each `AttestationEntry` records (component, version, fingerprint,
//! at) and carries a `prev_link` (FNV-1a of the previous entry's
//! canonical bytes). Tampering with any entry breaks the chain at
//! that index; verification walks from genesis and reports the
//! first break.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// FNV-1a 64-bit offset basis.
const FNV_OFFSET: u64 = 0xcbf29ce484222325;
/// FNV-1a 64-bit prime.
const FNV_PRIME: u64 = 0x100000001b3;

/// Genesis link value.
pub const GENESIS_LINK: u64 = 0;

/// One attestation entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationEntry {
    /// Component being attested (e.g., "kernel", "selfdef-engine").
    pub component: String,
    /// Version string.
    pub version: String,
    /// Fingerprint hex.
    pub fingerprint: String,
    /// ISO-8601 UTC timestamp.
    pub at: String,
    /// Link to previous entry (FNV-1a). 0 for first.
    pub prev_link: u64,
}

/// Chain envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationChain {
    /// Schema version.
    pub schema_version: String,
    /// Entries in arrival order.
    pub entries: Vec<AttestationEntry>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum AttestationError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty component.
    #[error("entry component empty")]
    EmptyComponent,
    /// Empty version.
    #[error("entry version empty")]
    EmptyVersion,
    /// Empty fingerprint.
    #[error("entry fingerprint empty")]
    EmptyFingerprint,
    /// Chain break at given index.
    #[error("chain break at index {index}: expected prev_link {expected:016x}, got {actual:016x}")]
    BrokenChain {
        /// 0-based break index.
        index: usize,
        /// expected.
        expected: u64,
        /// actual.
        actual: u64,
    },
}

impl AttestationChain {
    /// New empty chain.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            entries: Vec::new(),
        }
    }

    /// Append a new entry with `prev_link` auto-computed from the
    /// previous tail entry (or GENESIS_LINK for the first).
    pub fn append(
        &mut self,
        component: &str,
        version: &str,
        fingerprint: &str,
        at: &str,
    ) -> Result<(), AttestationError> {
        if component.is_empty() {
            return Err(AttestationError::EmptyComponent);
        }
        if version.is_empty() {
            return Err(AttestationError::EmptyVersion);
        }
        if fingerprint.is_empty() {
            return Err(AttestationError::EmptyFingerprint);
        }
        let prev_link = self.entries.last().map(link_of).unwrap_or(GENESIS_LINK);
        self.entries.push(AttestationEntry {
            component: component.into(),
            version: version.into(),
            fingerprint: fingerprint.into(),
            at: at.into(),
            prev_link,
        });
        Ok(())
    }

    /// Verify the chain from genesis. Returns Ok(()) when intact;
    /// Err with the first broken index otherwise.
    pub fn verify(&self) -> Result<(), AttestationError> {
        let mut expected_prev = GENESIS_LINK;
        for (i, e) in self.entries.iter().enumerate() {
            if e.prev_link != expected_prev {
                return Err(AttestationError::BrokenChain {
                    index: i,
                    expected: expected_prev,
                    actual: e.prev_link,
                });
            }
            expected_prev = link_of(e);
        }
        Ok(())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), AttestationError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(AttestationError::SchemaMismatch);
        }
        for e in &self.entries {
            if e.component.is_empty() {
                return Err(AttestationError::EmptyComponent);
            }
            if e.version.is_empty() {
                return Err(AttestationError::EmptyVersion);
            }
            if e.fingerprint.is_empty() {
                return Err(AttestationError::EmptyFingerprint);
            }
        }
        self.verify()
    }

    /// Compute the tip link (or GENESIS_LINK if empty).
    pub fn tip_link(&self) -> u64 {
        self.entries.last().map(link_of).unwrap_or(GENESIS_LINK)
    }
}

fn link_of(e: &AttestationEntry) -> u64 {
    let mut h = FNV_OFFSET;
    fn upd(mut h: u64, b: &[u8]) -> u64 {
        for &x in b {
            h ^= x as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        h
    }
    h = upd(h, e.component.as_bytes());
    h = upd(h, b"\x1f");
    h = upd(h, e.version.as_bytes());
    h = upd(h, b"\x1f");
    h = upd(h, e.fingerprint.as_bytes());
    h = upd(h, b"\x1f");
    h = upd(h, e.at.as_bytes());
    h = upd(h, b"\x1f");
    h = upd(h, &e.prev_link.to_be_bytes());
    h
}

impl Default for AttestationChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn populate(c: &mut AttestationChain) {
        c.append("kernel", "1.0", "f1", "t1").unwrap();
        c.append("selfdef-engine", "0.1", "f2", "t2").unwrap();
        c.append("sovereign-cockpit", "0.1", "f3", "t3").unwrap();
    }

    #[test]
    fn empty_chain_verifies() {
        AttestationChain::new().verify().unwrap();
    }

    #[test]
    fn single_entry_verifies() {
        let mut c = AttestationChain::new();
        c.append("kernel", "1.0", "f1", "t1").unwrap();
        c.verify().unwrap();
    }

    #[test]
    fn populated_chain_verifies() {
        let mut c = AttestationChain::new();
        populate(&mut c);
        c.verify().unwrap();
    }

    #[test]
    fn tampering_middle_entry_breaks_chain() {
        let mut c = AttestationChain::new();
        populate(&mut c);
        c.entries[1].fingerprint = "tampered".into();
        let err = c.verify().unwrap_err();
        match err {
            AttestationError::BrokenChain { index, .. } => assert_eq!(index, 2),
            _ => panic!(),
        }
    }

    #[test]
    fn tampering_prev_link_breaks() {
        let mut c = AttestationChain::new();
        populate(&mut c);
        c.entries[2].prev_link = 0xdeadbeef;
        let err = c.verify().unwrap_err();
        match err {
            AttestationError::BrokenChain { index, .. } => assert_eq!(index, 2),
            _ => panic!(),
        }
    }

    #[test]
    fn append_empty_fields_rejected() {
        let mut c = AttestationChain::new();
        assert!(matches!(
            c.append("", "v", "f", "t").unwrap_err(),
            AttestationError::EmptyComponent
        ));
        assert!(matches!(
            c.append("c", "", "f", "t").unwrap_err(),
            AttestationError::EmptyVersion
        ));
        assert!(matches!(
            c.append("c", "v", "", "t").unwrap_err(),
            AttestationError::EmptyFingerprint
        ));
    }

    #[test]
    fn tip_link_changes_with_entries() {
        let mut c = AttestationChain::new();
        assert_eq!(c.tip_link(), GENESIS_LINK);
        c.append("k", "1", "f", "t").unwrap();
        let a = c.tip_link();
        c.append("k2", "1", "f", "t").unwrap();
        let b = c.tip_link();
        assert_ne!(a, GENESIS_LINK);
        assert_ne!(a, b);
    }

    #[test]
    fn tip_link_deterministic() {
        let mut a = AttestationChain::new();
        let mut b = AttestationChain::new();
        for c in [&mut a, &mut b] {
            c.append("k", "1", "f", "t").unwrap();
            c.append("k2", "2", "g", "u").unwrap();
        }
        assert_eq!(a.tip_link(), b.tip_link());
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = AttestationChain::new();
        c.schema_version = "9.9.9".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            AttestationError::SchemaMismatch
        ));
    }

    #[test]
    fn validate_runs_verify() {
        let mut c = AttestationChain::new();
        populate(&mut c);
        c.entries[1].fingerprint = "broken".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            AttestationError::BrokenChain { .. }
        ));
    }

    #[test]
    fn entry_serde_roundtrip() {
        let mut c = AttestationChain::new();
        populate(&mut c);
        let j = serde_json::to_string(&c).unwrap();
        let back: AttestationChain = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
        back.verify().unwrap();
    }
}
