//! `selfdef-deficit-round-robin` — DRR scheduler.
//!
//! Flow{id, quantum, deficit, queue: VecDeque<u64>}. enqueue(id,
//! size) appends a packet of size bytes. service() rotates flows;
//! each pass adds quantum to the current flow's deficit and
//! services packets until the head exceeds deficit, then advances.
//! Empty flows are skipped (deficit reset to 0). Returns the
//! (flow_id, size) of the next packet served, or None if all idle.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Flow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Flow {
    /// Flow id.
    pub id: String,
    /// Quantum bytes per round.
    pub quantum: u64,
    /// Current deficit.
    pub deficit: u64,
    /// Queue of packet sizes (front = next).
    pub queue: VecDeque<u64>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeficitRoundRobin {
    /// Schema version.
    pub schema_version: String,
    /// Flows in round-robin order.
    pub flows: Vec<Flow>,
    /// Cursor.
    pub cursor: usize,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DrrError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("flow id empty")]
    EmptyId,
    /// Zero quantum.
    #[error("quantum must be >= 1")]
    ZeroQuantum,
    /// Zero size.
    #[error("packet size must be >= 1")]
    ZeroSize,
    /// Duplicate.
    #[error("duplicate flow id: {0}")]
    Duplicate(String),
    /// Unknown.
    #[error("unknown flow id: {0}")]
    Unknown(String),
    /// Cursor outside the flows range (corrupt/serde-bypassed state).
    #[error("cursor {cursor} out of range (flows len {len})")]
    CursorOutOfRange {
        /// Cursor value.
        cursor: usize,
        /// Number of flows.
        len: usize,
    },
}

impl DeficitRoundRobin {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            flows: Vec::new(),
            cursor: 0,
        }
    }

    /// Add a flow.
    pub fn add_flow(&mut self, id: &str, quantum: u64) -> Result<(), DrrError> {
        if id.is_empty() {
            return Err(DrrError::EmptyId);
        }
        if quantum == 0 {
            return Err(DrrError::ZeroQuantum);
        }
        if self.flows.iter().any(|f| f.id == id) {
            return Err(DrrError::Duplicate(id.into()));
        }
        self.flows.push(Flow {
            id: id.into(),
            quantum,
            deficit: 0,
            queue: VecDeque::new(),
        });
        Ok(())
    }

    /// Enqueue a packet on a flow.
    pub fn enqueue(&mut self, id: &str, size: u64) -> Result<(), DrrError> {
        if size == 0 {
            return Err(DrrError::ZeroSize);
        }
        let f = self
            .flows
            .iter_mut()
            .find(|f| f.id == id)
            .ok_or_else(|| DrrError::Unknown(id.into()))?;
        f.queue.push_back(size);
        Ok(())
    }

    /// Service the next packet. Returns (flow_id, size) or None.
    pub fn service(&mut self) -> Option<(String, u64)> {
        if self.flows.is_empty() {
            return None;
        }
        let n = self.flows.len();
        // `cursor` is advanced only via `% n`, so it stays < flows.len() under
        // normal use — but serde deserialization bypasses new()/the advance
        // path and can persist a cursor >= len. The `self.flows[self.cursor]`
        // index below would then panic (out-of-bounds, in every build).
        // Normalize back into range rather than crash.
        if self.cursor >= n {
            self.cursor = 0;
        }
        // Find a flow that can serve at least one packet within one
        // full sweep. Each sweep adds quantum to non-empty flows; if
        // none can serve, all are empty and we return None.
        for _sweep in 0..2 {
            let mut any_non_empty = false;
            for _ in 0..n {
                let i = self.cursor;
                let f = &mut self.flows[i];
                if !f.queue.is_empty() {
                    any_non_empty = true;
                    f.deficit = f.deficit.saturating_add(f.quantum);
                    if let Some(&head) = f.queue.front() {
                        if head <= f.deficit {
                            f.deficit -= head;
                            f.queue.pop_front();
                            // Stay on this flow on next call if more
                            // queue + deficit remains; for simplicity
                            // advance the cursor here.
                            self.cursor = (self.cursor + 1) % n;
                            return Some((f.id.clone(), head));
                        }
                    }
                } else {
                    // Empty: reset deficit per DRR semantics.
                    f.deficit = 0;
                }
                self.cursor = (self.cursor + 1) % n;
            }
            if !any_non_empty {
                return None;
            }
        }
        None
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DrrError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(DrrError::SchemaMismatch);
        }
        for f in &self.flows {
            if f.id.is_empty() {
                return Err(DrrError::EmptyId);
            }
            if f.quantum == 0 {
                return Err(DrrError::ZeroQuantum);
            }
        }
        if !self.flows.is_empty() && self.cursor >= self.flows.len() {
            return Err(DrrError::CursorOutOfRange {
                cursor: self.cursor,
                len: self.flows.len(),
            });
        }
        Ok(())
    }
}

impl Default for DeficitRoundRobin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_range_cursor_serde_bypass_does_not_panic() {
        // cursor is advanced only via `% n`, so it stays in range under normal
        // use; serde can persist a cursor >= flows.len(). service() indexes
        // self.flows[self.cursor] after only an is_empty() guard — an OOB panic
        // in every build. The normalize-to-0 guard must keep it serving.
        let mut s = DeficitRoundRobin::new();
        s.add_flow("a", 1000).unwrap();
        s.enqueue("a", 100).unwrap();
        s.cursor = 99; // serde-bypassed: way past flows.len() == 1
        // Must not panic, and must still serve the queued packet.
        assert_eq!(s.service(), Some(("a".to_string(), 100)));
    }

    #[test]
    fn out_of_range_cursor_rejected_by_validate() {
        let mut s = DeficitRoundRobin::new();
        s.add_flow("a", 1000).unwrap();
        s.cursor = 42;
        assert!(matches!(
            s.validate().unwrap_err(),
            DrrError::CursorOutOfRange { cursor: 42, len: 1 }
        ));
    }

    #[test]
    fn two_flows_quantum_ratio() {
        let mut s = DeficitRoundRobin::new();
        s.add_flow("a", 1000).unwrap();
        s.add_flow("b", 500).unwrap();
        for _ in 0..10 {
            s.enqueue("a", 100).unwrap();
        }
        for _ in 0..10 {
            s.enqueue("b", 100).unwrap();
        }
        let mut served_a = 0u64;
        let mut served_b = 0u64;
        // Service everything.
        while let Some((id, _)) = s.service() {
            if id == "a" {
                served_a += 1;
            } else {
                served_b += 1;
            }
            if served_a + served_b > 30 {
                break;
            }
        }
        // Both should be fully drained.
        assert_eq!(served_a, 10);
        assert_eq!(served_b, 10);
    }

    #[test]
    fn idle_returns_none() {
        let mut s = DeficitRoundRobin::new();
        s.add_flow("a", 100).unwrap();
        assert!(s.service().is_none());
    }

    #[test]
    fn empty_no_flows_returns_none() {
        let mut s = DeficitRoundRobin::new();
        assert!(s.service().is_none());
    }

    #[test]
    fn unknown_flow_rejected_on_enqueue() {
        let mut s = DeficitRoundRobin::new();
        assert!(matches!(
            s.enqueue("a", 10).unwrap_err(),
            DrrError::Unknown(_)
        ));
    }

    #[test]
    fn duplicate_flow_rejected() {
        let mut s = DeficitRoundRobin::new();
        s.add_flow("a", 100).unwrap();
        assert!(matches!(
            s.add_flow("a", 100).unwrap_err(),
            DrrError::Duplicate(_)
        ));
    }

    #[test]
    fn zero_inputs_rejected() {
        let mut s = DeficitRoundRobin::new();
        assert!(matches!(
            s.add_flow("", 100).unwrap_err(),
            DrrError::EmptyId
        ));
        assert!(matches!(
            s.add_flow("a", 0).unwrap_err(),
            DrrError::ZeroQuantum
        ));
        s.add_flow("a", 100).unwrap();
        assert!(matches!(s.enqueue("a", 0).unwrap_err(), DrrError::ZeroSize));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = DeficitRoundRobin::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            DrrError::SchemaMismatch
        ));
    }

    #[test]
    fn drr_serde_roundtrip() {
        let mut s = DeficitRoundRobin::new();
        s.add_flow("a", 100).unwrap();
        s.enqueue("a", 50).unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: DeficitRoundRobin = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
