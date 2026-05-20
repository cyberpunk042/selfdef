//! `selfdef-evidence-merkle-chain` — hash-chained evidence log.
//!
//! Each `Link { seq, payload_hash, prev_chain_hash, chain_hash }`
//! is appended via `append(payload, ts_ms)`. The chain_hash =
//! `FNV-1a-64(seq || ":" || ts || ":" || payload_hash || ":" ||
//! prev_chain_hash)`. Any tampering breaks the chain.
//!
//! `verify_continuity()` walks the chain and reports the first
//! offending index, or Ok.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// FNV-1a 64.
fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// One chain link.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Link {
    /// Monotonic seq.
    pub seq: u64,
    /// Hash of payload.
    pub payload_hash: u64,
    /// Hash of prev link's chain_hash (0 for first).
    pub prev_chain_hash: u64,
    /// Hash for this link.
    pub chain_hash: u64,
    /// Recorded ts.
    pub ts_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceMerkleChain {
    /// Schema version.
    pub schema_version: String,
    /// Append-only links.
    pub links: Vec<Link>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ChainError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Continuity break.
    #[error("continuity broken at index {index}: prev_chain_hash {prev_in_link} != computed {computed}")]
    ContinuityBreak {
        /// index.
        index: usize,
        /// prev_in_link.
        prev_in_link: u64,
        /// computed.
        computed: u64,
    },
    /// Self-hash mismatch.
    #[error("self-hash mismatch at index {0}")]
    SelfHashMismatch(usize),
    /// Sequence break.
    #[error("seq break at index {0}: expected {expected}, got {got}", expected = .1, got = .2)]
    SeqBreak(usize, u64, u64),
}

fn compute_chain_hash(seq: u64, ts_ms: u64, payload_hash: u64, prev_chain_hash: u64) -> u64 {
    let mut s = String::new();
    s.push_str(&seq.to_string());
    s.push(':');
    s.push_str(&ts_ms.to_string());
    s.push(':');
    s.push_str(&format!("{payload_hash:016x}"));
    s.push(':');
    s.push_str(&format!("{prev_chain_hash:016x}"));
    fnv1a_64(s.as_bytes())
}

impl EvidenceMerkleChain {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            links: Vec::new(),
        }
    }

    /// Append.
    pub fn append(&mut self, payload: &[u8], ts_ms: u64) -> Link {
        let seq = self.links.len() as u64 + 1;
        let payload_hash = fnv1a_64(payload);
        let prev_chain_hash = self.links.last().map(|l| l.chain_hash).unwrap_or(0);
        let chain_hash = compute_chain_hash(seq, ts_ms, payload_hash, prev_chain_hash);
        let link = Link { seq, payload_hash, prev_chain_hash, chain_hash, ts_ms };
        self.links.push(link.clone());
        link
    }

    /// Verify the entire chain.
    pub fn verify_continuity(&self) -> Result<(), ChainError> {
        let mut prev = 0u64;
        for (i, l) in self.links.iter().enumerate() {
            let expected_seq = (i as u64) + 1;
            if l.seq != expected_seq {
                return Err(ChainError::SeqBreak(i, expected_seq, l.seq));
            }
            if l.prev_chain_hash != prev {
                return Err(ChainError::ContinuityBreak {
                    index: i,
                    prev_in_link: l.prev_chain_hash,
                    computed: prev,
                });
            }
            let computed = compute_chain_hash(l.seq, l.ts_ms, l.payload_hash, l.prev_chain_hash);
            if computed != l.chain_hash {
                return Err(ChainError::SelfHashMismatch(i));
            }
            prev = l.chain_hash;
        }
        Ok(())
    }

    /// Head hash (last link's chain_hash, or 0 if empty).
    pub fn head_hash(&self) -> u64 {
        self.links.last().map(|l| l.chain_hash).unwrap_or(0)
    }

    /// Length.
    pub fn len(&self) -> usize {
        self.links.len()
    }

    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ChainError> {
        if self.schema_version != SCHEMA_VERSION { return Err(ChainError::SchemaMismatch); }
        self.verify_continuity()
    }
}

impl Default for EvidenceMerkleChain {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_chain_valid() {
        let c = EvidenceMerkleChain::new();
        assert!(c.verify_continuity().is_ok());
        assert_eq!(c.head_hash(), 0);
    }

    #[test]
    fn single_append() {
        let mut c = EvidenceMerkleChain::new();
        let l = c.append(b"hello", 100);
        assert_eq!(l.seq, 1);
        assert_eq!(l.prev_chain_hash, 0);
        assert!(c.verify_continuity().is_ok());
    }

    #[test]
    fn chained_append() {
        let mut c = EvidenceMerkleChain::new();
        let a = c.append(b"a", 0);
        let b = c.append(b"b", 1);
        assert_eq!(b.prev_chain_hash, a.chain_hash);
        assert!(c.verify_continuity().is_ok());
    }

    #[test]
    fn tamper_payload_detected() {
        let mut c = EvidenceMerkleChain::new();
        c.append(b"a", 0);
        c.append(b"b", 1);
        // Tamper the payload_hash of first link.
        c.links[0].payload_hash = 0xDEADBEEF;
        assert!(matches!(c.verify_continuity().unwrap_err(), ChainError::SelfHashMismatch(0)));
    }

    #[test]
    fn tamper_break_continuity() {
        let mut c = EvidenceMerkleChain::new();
        c.append(b"a", 0);
        c.append(b"b", 1);
        c.append(b"c", 2);
        // Tamper a middle chain_hash without updating downstream.
        c.links[1].chain_hash = c.links[1].chain_hash.wrapping_add(1);
        // The middle link's self-hash check will fail before downstream check.
        assert!(c.verify_continuity().is_err());
    }

    #[test]
    fn tamper_seq_detected() {
        let mut c = EvidenceMerkleChain::new();
        c.append(b"a", 0);
        c.append(b"b", 1);
        c.links[1].seq = 99;
        assert!(matches!(c.verify_continuity().unwrap_err(), ChainError::SeqBreak(_, _, _)));
    }

    #[test]
    fn head_hash_changes() {
        let mut c = EvidenceMerkleChain::new();
        c.append(b"a", 0);
        let h1 = c.head_hash();
        c.append(b"b", 0);
        let h2 = c.head_hash();
        assert_ne!(h1, h2);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = EvidenceMerkleChain::new();
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), ChainError::SchemaMismatch));
    }

    #[test]
    fn chain_serde_roundtrip() {
        let mut c = EvidenceMerkleChain::new();
        c.append(b"a", 0);
        c.append(b"b", 1);
        let j = serde_json::to_string(&c).unwrap();
        let back: EvidenceMerkleChain = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
        assert!(back.verify_continuity().is_ok());
    }
}
