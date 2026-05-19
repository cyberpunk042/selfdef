//! `selfdef-replay-ring` — bounded FIFO replay buffer.
//!
//! Fixed-capacity ring of `ReplayFrame` records. Once the capacity is
//! reached, the next push drops the oldest. The daemon backs this with
//! the on-disk replay buffer; the in-memory ring lets operators "rewind"
//! the last N events instantly without hitting disk.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use std::collections::VecDeque;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One replayable frame.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayFrame {
    /// Monotonic sequence number assigned at push time.
    pub seq: u64,
    /// ISO-8601 UTC.
    pub at: String,
    /// M049 trace_id linking the frame to its decision/span/audit.
    pub trace_id: String,
    /// Source collector (free-text kind name; "auditd" / "tetragon" / "internal").
    pub source: String,
    /// Opaque event-bus payload (canonical JSON string).
    pub payload: String,
}

/// Ring state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayRing {
    /// Schema version.
    pub schema_version: String,
    /// Fixed capacity.
    pub capacity: u32,
    /// Next seq to assign.
    pub next_seq: u64,
    /// Frames (oldest first).
    pub frames: VecDeque<ReplayFrame>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RingError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Capacity 0.
    #[error("capacity 0 disallowed")]
    ZeroCapacity,
    /// Capacity exceeded.
    #[error("frames len {len} > capacity {cap}")]
    OverCapacity {
        /// Length.
        len: usize,
        /// Capacity.
        cap: u32,
    },
    /// Seq monotonicity violated.
    #[error("frame {idx} seq {got} <= previous {prev}")]
    SeqNonMonotonic {
        /// idx.
        idx: usize,
        /// got.
        got: u64,
        /// prev.
        prev: u64,
    },
}

impl ReplayRing {
    /// New ring with the given capacity.
    pub fn new(capacity: u32) -> Result<Self, RingError> {
        if capacity == 0 { return Err(RingError::ZeroCapacity); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            capacity,
            next_seq: 0,
            frames: VecDeque::with_capacity(capacity as usize),
        })
    }

    /// Push a frame; assigns seq automatically. Drops the oldest if at capacity.
    /// Returns the assigned seq.
    pub fn push(&mut self, at: &str, trace_id: &str, source: &str, payload: &str) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        let frame = ReplayFrame {
            seq,
            at: at.into(),
            trace_id: trace_id.into(),
            source: source.into(),
            payload: payload.into(),
        };
        if self.frames.len() as u32 >= self.capacity {
            self.frames.pop_front();
        }
        self.frames.push_back(frame);
        seq
    }

    /// Number of frames currently retained.
    pub fn len(&self) -> usize { self.frames.len() }

    /// Is the ring empty?
    pub fn is_empty(&self) -> bool { self.frames.is_empty() }

    /// Iterate frames oldest → newest.
    pub fn iter(&self) -> impl Iterator<Item = &ReplayFrame> {
        self.frames.iter()
    }

    /// Iterate the last `n` frames (or all if fewer).
    pub fn tail(&self, n: usize) -> Vec<&ReplayFrame> {
        let start = self.frames.len().saturating_sub(n);
        self.frames.iter().skip(start).collect()
    }

    /// Look up by seq.
    pub fn get(&self, seq: u64) -> Option<&ReplayFrame> {
        self.frames.iter().find(|f| f.seq == seq)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RingError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RingError::SchemaMismatch);
        }
        if self.capacity == 0 { return Err(RingError::ZeroCapacity); }
        if self.frames.len() as u32 > self.capacity {
            return Err(RingError::OverCapacity { len: self.frames.len(), cap: self.capacity });
        }
        let mut prev: Option<u64> = None;
        for (idx, f) in self.frames.iter().enumerate() {
            if let Some(p) = prev {
                if f.seq <= p {
                    return Err(RingError::SeqNonMonotonic { idx, got: f.seq, prev: p });
                }
            }
            prev = Some(f.seq);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_zero_rejected() {
        assert!(matches!(ReplayRing::new(0).unwrap_err(), RingError::ZeroCapacity));
    }

    #[test]
    fn empty_ring_validates() {
        ReplayRing::new(4).unwrap().validate().unwrap();
    }

    #[test]
    fn push_assigns_monotonic_seq() {
        let mut r = ReplayRing::new(4).unwrap();
        assert_eq!(r.push("t", "tr-1", "auditd", "{}"), 0);
        assert_eq!(r.push("t", "tr-2", "tetragon", "{}"), 1);
        assert_eq!(r.push("t", "tr-3", "ebpf", "{}"), 2);
        r.validate().unwrap();
    }

    #[test]
    fn overflow_drops_oldest_keeps_capacity() {
        let mut r = ReplayRing::new(3).unwrap();
        for i in 0..6 {
            r.push("t", &format!("tr-{i}"), "internal", "{}");
        }
        assert_eq!(r.len(), 3);
        // Oldest seq retained should be 3, newest 5.
        let seqs: Vec<u64> = r.iter().map(|f| f.seq).collect();
        assert_eq!(seqs, vec![3, 4, 5]);
    }

    #[test]
    fn tail_returns_last_n() {
        let mut r = ReplayRing::new(10).unwrap();
        for i in 0..5 {
            r.push("t", &format!("tr-{i}"), "x", "{}");
        }
        let t = r.tail(3);
        let seqs: Vec<u64> = t.iter().map(|f| f.seq).collect();
        assert_eq!(seqs, vec![2, 3, 4]);
    }

    #[test]
    fn tail_caps_at_len() {
        let mut r = ReplayRing::new(10).unwrap();
        r.push("t", "tr-0", "x", "{}");
        assert_eq!(r.tail(99).len(), 1);
    }

    #[test]
    fn get_by_seq() {
        let mut r = ReplayRing::new(4).unwrap();
        r.push("t", "tr-0", "x", "{}");
        r.push("t", "tr-1", "y", "{}");
        assert!(r.get(0).is_some());
        assert!(r.get(99).is_none());
    }

    #[test]
    fn over_capacity_invalidated() {
        let mut r = ReplayRing::new(2).unwrap();
        r.frames.push_back(ReplayFrame { seq: 0, at: "t".into(), trace_id: "x".into(), source: "x".into(), payload: "{}".into() });
        r.frames.push_back(ReplayFrame { seq: 1, at: "t".into(), trace_id: "x".into(), source: "x".into(), payload: "{}".into() });
        r.frames.push_back(ReplayFrame { seq: 2, at: "t".into(), trace_id: "x".into(), source: "x".into(), payload: "{}".into() });
        assert!(matches!(r.validate().unwrap_err(), RingError::OverCapacity { len: 3, cap: 2 }));
    }

    #[test]
    fn seq_non_monotonic_caught() {
        let mut r = ReplayRing::new(4).unwrap();
        r.frames.push_back(ReplayFrame { seq: 5, at: "t".into(), trace_id: "x".into(), source: "x".into(), payload: "{}".into() });
        r.frames.push_back(ReplayFrame { seq: 3, at: "t".into(), trace_id: "x".into(), source: "x".into(), payload: "{}".into() });
        assert!(matches!(r.validate().unwrap_err(), RingError::SeqNonMonotonic { idx: 1, got: 3, prev: 5 }));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = ReplayRing::new(2).unwrap();
        r.schema_version = "9.9.9".into();
        assert!(matches!(r.validate().unwrap_err(), RingError::SchemaMismatch));
    }

    #[test]
    fn ring_serde_roundtrip() {
        let mut r = ReplayRing::new(8).unwrap();
        r.push("t", "tr-0", "auditd", "{\"x\":1}");
        r.push("t", "tr-1", "ebpf", "{\"y\":2}");
        let j = serde_json::to_string(&r).unwrap();
        let back: ReplayRing = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
