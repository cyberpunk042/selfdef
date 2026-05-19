//! `selfdef-evidence-chain-link` — chain-hash for evidence ledger.
//!
//! Each entry stores: (sequence, payload, prev_link_hash, this_link_hash)
//! where `this_link_hash = fnv1a64(prev_link_hash || payload)`. The
//! sentinel `prev_link_hash` for the first entry is fixed `"0x00"`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Genesis prev_link_hash for the first entry.
pub const GENESIS_PREV: &str = "0x0000000000000000";

/// One chained entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceLink {
    /// Monotonic sequence (0 = genesis).
    pub sequence: u64,
    /// Canonical-JSON payload (opaque to this crate).
    pub payload: String,
    /// Previous link's hash; "0x00..00" for genesis.
    pub prev_link_hash: String,
    /// This link's hash.
    pub this_link_hash: String,
}

/// Chain envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceChain {
    /// Schema version.
    pub schema_version: String,
    /// Links in sequence order.
    pub links: Vec<EvidenceLink>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ChainLinkError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Sequence non-monotonic.
    #[error("link {idx} sequence {got} expected {expected}")]
    SequenceNonMonotonic {
        /// idx.
        idx: usize,
        /// got.
        got: u64,
        /// expected.
        expected: u64,
    },
    /// prev_link_hash doesn't match the previous link's this_link_hash.
    #[error("link {idx} prev_link_hash mismatch: stored={stored}, expected={expected}")]
    PrevHashMismatch {
        /// idx.
        idx: usize,
        /// stored.
        stored: String,
        /// expected.
        expected: String,
    },
    /// this_link_hash doesn't match recomputed value.
    #[error("link {idx} this_link_hash mismatch: stored={stored}, recomputed={recomputed}")]
    ThisHashMismatch {
        /// idx.
        idx: usize,
        /// stored.
        stored: String,
        /// recomputed.
        recomputed: String,
    },
}

/// FNV-1a 64-bit.
pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn link_hash(prev: &str, payload: &str) -> String {
    let mut concat = Vec::with_capacity(prev.len() + 1 + payload.len());
    concat.extend_from_slice(prev.as_bytes());
    concat.push(0);
    concat.extend_from_slice(payload.as_bytes());
    let h = fnv1a_64(&concat);
    format!("0x{h:016x}")
}

impl EvidenceChain {
    /// New empty chain.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            links: Vec::new(),
        }
    }

    /// Append a new entry; computes prev/this hashes.
    pub fn append(&mut self, payload: &str) {
        let sequence = self.links.len() as u64;
        let prev = if let Some(last) = self.links.last() {
            last.this_link_hash.clone()
        } else {
            GENESIS_PREV.into()
        };
        let this = link_hash(&prev, payload);
        self.links.push(EvidenceLink {
            sequence,
            payload: payload.into(),
            prev_link_hash: prev,
            this_link_hash: this,
        });
    }

    /// Length.
    pub fn len(&self) -> usize { self.links.len() }

    /// Is empty.
    pub fn is_empty(&self) -> bool { self.links.is_empty() }

    /// Most recent hash (for chain advance).
    pub fn tip(&self) -> &str {
        match self.links.last() {
            Some(l) => &l.this_link_hash,
            None => GENESIS_PREV,
        }
    }

    /// Validate the chain.
    pub fn validate(&self) -> Result<(), ChainLinkError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ChainLinkError::SchemaMismatch);
        }
        let mut expected_prev: String = GENESIS_PREV.into();
        for (idx, l) in self.links.iter().enumerate() {
            let expected_seq = idx as u64;
            if l.sequence != expected_seq {
                return Err(ChainLinkError::SequenceNonMonotonic {
                    idx, got: l.sequence, expected: expected_seq,
                });
            }
            if l.prev_link_hash != expected_prev {
                return Err(ChainLinkError::PrevHashMismatch {
                    idx,
                    stored: l.prev_link_hash.clone(),
                    expected: expected_prev,
                });
            }
            let recomputed = link_hash(&l.prev_link_hash, &l.payload);
            if l.this_link_hash != recomputed {
                return Err(ChainLinkError::ThisHashMismatch {
                    idx,
                    stored: l.this_link_hash.clone(),
                    recomputed,
                });
            }
            expected_prev = l.this_link_hash.clone();
        }
        Ok(())
    }
}

impl Default for EvidenceChain {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_chain_validates() {
        EvidenceChain::new().validate().unwrap();
    }

    #[test]
    fn append_chains_correctly() {
        let mut c = EvidenceChain::new();
        c.append("{\"a\":1}");
        c.append("{\"a\":2}");
        c.append("{\"a\":3}");
        c.validate().unwrap();
        assert_eq!(c.len(), 3);
        // tip = last this_link_hash
        assert_eq!(c.tip(), c.links[2].this_link_hash);
    }

    #[test]
    fn first_link_prev_is_genesis() {
        let mut c = EvidenceChain::new();
        c.append("x");
        assert_eq!(c.links[0].prev_link_hash, GENESIS_PREV);
    }

    #[test]
    fn this_hash_deterministic() {
        let mut a = EvidenceChain::new();
        let mut b = EvidenceChain::new();
        a.append("payload");
        b.append("payload");
        assert_eq!(a.links[0].this_link_hash, b.links[0].this_link_hash);
    }

    #[test]
    fn tampered_payload_caught() {
        let mut c = EvidenceChain::new();
        c.append("a");
        c.append("b");
        c.links[1].payload = "tampered".into();
        match c.validate().unwrap_err() {
            ChainLinkError::ThisHashMismatch { idx, .. } => assert_eq!(idx, 1),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn tampered_prev_hash_caught() {
        let mut c = EvidenceChain::new();
        c.append("a");
        c.append("b");
        c.links[1].prev_link_hash = "0xdeadbeefdeadbeef".into();
        let err = c.validate().unwrap_err();
        // Either prev mismatch first or this-hash mismatch (since prev fed into hash). Accept either.
        assert!(matches!(err, ChainLinkError::PrevHashMismatch { idx: 1, .. }
                              | ChainLinkError::ThisHashMismatch { idx: 1, .. }));
    }

    #[test]
    fn sequence_non_monotonic_caught() {
        let mut c = EvidenceChain::new();
        c.append("a");
        c.append("b");
        c.links[1].sequence = 99;
        match c.validate().unwrap_err() {
            ChainLinkError::SequenceNonMonotonic { idx, got, expected } => {
                assert_eq!(idx, 1);
                assert_eq!(got, 99);
                assert_eq!(expected, 1);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = EvidenceChain::new();
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), ChainLinkError::SchemaMismatch));
    }

    #[test]
    fn tip_genesis_when_empty() {
        let c = EvidenceChain::new();
        assert_eq!(c.tip(), GENESIS_PREV);
    }

    #[test]
    fn chain_serde_roundtrip() {
        let mut c = EvidenceChain::new();
        c.append("a"); c.append("b");
        let j = serde_json::to_string(&c).unwrap();
        let back: EvidenceChain = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
