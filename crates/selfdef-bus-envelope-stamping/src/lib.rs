//! `selfdef-bus-envelope-stamping` — emitter-side envelope stamping.
//!
//! Each emitter id maintains a monotonic sequence. `stamp(emitter,
//! topic, payload, ts_ms)` returns an `Envelope { emitter, seq,
//! topic, ts_ms, payload_hash }` where `payload_hash` is FNV-1a 64.
//! `verify(envelope, payload)` recomputes and compares the hash;
//! returns `Ok(())` / `Err(HashMismatch)`. `recover_emitter_state(
//! emitter, last_seq)` resets the next seq (e.g. after replay).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    /// Emitter id.
    pub emitter: String,
    /// Sequence number.
    pub seq: u64,
    /// Topic label.
    pub topic: String,
    /// Timestamp.
    pub ts_ms: u64,
    /// FNV-1a 64 of payload.
    pub payload_hash: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BusEnvelopeStamping {
    /// Schema version.
    pub schema_version: String,
    /// emitter → next seq.
    pub next_seq: BTreeMap<String, u64>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum StampError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty emitter.
    #[error("emitter empty")]
    EmptyEmitter,
    /// Empty topic.
    #[error("topic empty")]
    EmptyTopic,
    /// Hash mismatch.
    #[error("payload hash mismatch: stamped {stamped:016x} != recomputed {recomputed:016x}")]
    HashMismatch {
        /// stamped.
        stamped: u64,
        /// recomputed.
        recomputed: u64,
    },
    /// Non-monotonic seq recover.
    #[error("recover would not advance seq: existing {existing} >= proposed_next {proposed}")]
    BackwardRecover {
        /// existing.
        existing: u64,
        /// proposed.
        proposed: u64,
    },
}

/// FNV-1a 64.
pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

impl BusEnvelopeStamping {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            next_seq: BTreeMap::new(),
        }
    }

    /// Stamp an envelope.
    pub fn stamp(&mut self, emitter: &str, topic: &str, payload: &[u8], ts_ms: u64) -> Result<Envelope, StampError> {
        if emitter.is_empty() { return Err(StampError::EmptyEmitter); }
        if topic.is_empty() { return Err(StampError::EmptyTopic); }
        let seq = *self.next_seq.entry(emitter.into()).or_insert(1);
        *self.next_seq.get_mut(emitter).unwrap() = seq.wrapping_add(1);
        Ok(Envelope {
            emitter: emitter.into(),
            seq,
            topic: topic.into(),
            ts_ms,
            payload_hash: fnv1a_64(payload),
        })
    }

    /// Verify.
    pub fn verify(env: &Envelope, payload: &[u8]) -> Result<(), StampError> {
        let h = fnv1a_64(payload);
        if h != env.payload_hash {
            return Err(StampError::HashMismatch { stamped: env.payload_hash, recomputed: h });
        }
        Ok(())
    }

    /// Advance the next seq counter past `last_observed_seq`.
    pub fn recover_emitter_state(&mut self, emitter: &str, last_observed_seq: u64) -> Result<(), StampError> {
        if emitter.is_empty() { return Err(StampError::EmptyEmitter); }
        let proposed = last_observed_seq.wrapping_add(1);
        let existing = *self.next_seq.get(emitter).unwrap_or(&1);
        if existing >= proposed {
            return Err(StampError::BackwardRecover { existing, proposed });
        }
        self.next_seq.insert(emitter.into(), proposed);
        Ok(())
    }

    /// Next seq for emitter.
    pub fn next(&self, emitter: &str) -> u64 {
        self.next_seq.get(emitter).copied().unwrap_or(1)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), StampError> {
        if self.schema_version != SCHEMA_VERSION { return Err(StampError::SchemaMismatch); }
        for k in self.next_seq.keys() {
            if k.is_empty() { return Err(StampError::EmptyEmitter); }
        }
        Ok(())
    }
}

impl Default for BusEnvelopeStamping {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_then_verify() {
        let mut s = BusEnvelopeStamping::new();
        let e = s.stamp("e1", "t1", b"hello", 0).unwrap();
        assert!(BusEnvelopeStamping::verify(&e, b"hello").is_ok());
    }

    #[test]
    fn verify_tamper_detected() {
        let mut s = BusEnvelopeStamping::new();
        let e = s.stamp("e1", "t1", b"hello", 0).unwrap();
        assert!(BusEnvelopeStamping::verify(&e, b"goodbye").is_err());
    }

    #[test]
    fn seq_monotonic_per_emitter() {
        let mut s = BusEnvelopeStamping::new();
        let e1 = s.stamp("e1", "t", b"a", 0).unwrap();
        let e2 = s.stamp("e1", "t", b"b", 0).unwrap();
        assert_eq!(e1.seq, 1);
        assert_eq!(e2.seq, 2);
    }

    #[test]
    fn seqs_independent_across_emitters() {
        let mut s = BusEnvelopeStamping::new();
        let a = s.stamp("e1", "t", b"a", 0).unwrap();
        let b = s.stamp("e2", "t", b"a", 0).unwrap();
        assert_eq!(a.seq, 1);
        assert_eq!(b.seq, 1);
    }

    #[test]
    fn recover_advances() {
        let mut s = BusEnvelopeStamping::new();
        s.recover_emitter_state("e1", 100).unwrap();
        assert_eq!(s.next("e1"), 101);
        let e = s.stamp("e1", "t", b"x", 0).unwrap();
        assert_eq!(e.seq, 101);
    }

    #[test]
    fn recover_backward_rejected() {
        let mut s = BusEnvelopeStamping::new();
        s.stamp("e1", "t", b"x", 0).unwrap(); // seq 1
        s.stamp("e1", "t", b"y", 0).unwrap(); // seq 2
        // next is 3; recovering "saw last_seq=1" implies proposed=2, < existing 3 → reject.
        assert!(matches!(s.recover_emitter_state("e1", 1).unwrap_err(), StampError::BackwardRecover { .. }));
    }

    #[test]
    fn fnv1a_known_vector() {
        // FNV-1a-64 of empty string is the offset basis itself.
        assert_eq!(fnv1a_64(b""), 0xcbf29ce484222325);
        // Different inputs produce different hashes.
        assert_ne!(fnv1a_64(b"abc"), fnv1a_64(b"abd"));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut s = BusEnvelopeStamping::new();
        assert!(matches!(s.stamp("", "t", b"", 0).unwrap_err(), StampError::EmptyEmitter));
        assert!(matches!(s.stamp("e", "", b"", 0).unwrap_err(), StampError::EmptyTopic));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = BusEnvelopeStamping::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), StampError::SchemaMismatch));
    }

    #[test]
    fn envelope_serde_roundtrip() {
        let mut s = BusEnvelopeStamping::new();
        let e = s.stamp("e1", "t", b"payload", 100).unwrap();
        let j = serde_json::to_string(&e).unwrap();
        let back: Envelope = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }
}
