//! `selfdef-sequence-gap-detector` — finds missing seq numbers.
//!
//! observe(seq) tracks expected_next. If seq > expected_next, the
//! interval [expected_next, seq) is recorded as a Gap. seq <
//! expected_next is recorded as out_of_order count (the data is
//! either a duplicate or a late retransmission — both are auditable
//! anomalies but neither closes prior gaps automatically; close_gap
//! does that explicitly).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Gap [start, end) — half-open.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Gap {
    /// Inclusive start.
    pub start: u64,
    /// Exclusive end.
    pub end: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SequenceGapDetector {
    /// Schema version.
    pub schema_version: String,
    /// Whether we've seen anything.
    pub seeded: bool,
    /// Next expected seq.
    pub expected_next: u64,
    /// Gaps observed (insertion order).
    pub gaps: Vec<Gap>,
    /// Count of seqs strictly less than expected_next at time of
    /// observe (duplicates + late retransmits).
    pub out_of_order: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SeqError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Gap not found.
    #[error("gap not found")]
    GapNotFound,
}

impl SequenceGapDetector {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            seeded: false,
            expected_next: 0,
            gaps: Vec::new(),
            out_of_order: 0,
        }
    }

    /// Observe a sequence number.
    pub fn observe(&mut self, seq: u64) {
        if !self.seeded {
            self.seeded = true;
            self.expected_next = seq.saturating_add(1);
            return;
        }
        if seq == self.expected_next {
            self.expected_next = seq.saturating_add(1);
        } else if seq > self.expected_next {
            self.gaps.push(Gap {
                start: self.expected_next,
                end: seq,
            });
            self.expected_next = seq.saturating_add(1);
        } else {
            // seq < expected_next.
            self.out_of_order = self.out_of_order.saturating_add(1);
        }
    }

    /// Explicitly close a gap (e.g. a retransmit covered it).
    /// Splits the matching gap if `seq` is interior.
    pub fn close_gap(&mut self, seq: u64) -> Result<(), SeqError> {
        let idx = self
            .gaps
            .iter()
            .position(|g| seq >= g.start && seq < g.end)
            .ok_or(SeqError::GapNotFound)?;
        let g = self.gaps[idx].clone();
        self.gaps.remove(idx);
        // Re-insert remaining halves in the same position.
        let mut insert_at = idx;
        if seq + 1 < g.end {
            self.gaps.insert(
                insert_at,
                Gap {
                    start: seq + 1,
                    end: g.end,
                },
            );
        }
        if seq > g.start {
            self.gaps.insert(
                insert_at,
                Gap {
                    start: g.start,
                    end: seq,
                },
            );
            insert_at += 1;
        }
        let _ = insert_at;
        Ok(())
    }

    /// Outstanding (uncovered) count across all gaps.
    pub fn missing(&self) -> u64 {
        self.gaps
            .iter()
            .map(|g| g.end.saturating_sub(g.start))
            .sum()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), SeqError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SeqError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for SequenceGapDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contiguous_no_gaps() {
        let mut d = SequenceGapDetector::new();
        d.observe(10);
        d.observe(11);
        d.observe(12);
        assert!(d.gaps.is_empty());
        assert_eq!(d.expected_next, 13);
    }

    #[test]
    fn single_gap_recorded() {
        let mut d = SequenceGapDetector::new();
        d.observe(10);
        d.observe(13);
        assert_eq!(d.gaps, vec![Gap { start: 11, end: 13 }]);
        assert_eq!(d.missing(), 2);
        assert_eq!(d.expected_next, 14);
    }

    #[test]
    fn duplicate_increments_out_of_order() {
        let mut d = SequenceGapDetector::new();
        d.observe(10);
        d.observe(11);
        d.observe(11);
        assert_eq!(d.out_of_order, 1);
        assert!(d.gaps.is_empty());
    }

    #[test]
    fn close_gap_full() {
        let mut d = SequenceGapDetector::new();
        d.observe(10);
        d.observe(13);
        d.close_gap(11).unwrap();
        // Remaining: 12..13.
        assert_eq!(d.gaps, vec![Gap { start: 12, end: 13 }]);
        d.close_gap(12).unwrap();
        assert!(d.gaps.is_empty());
    }

    #[test]
    fn close_gap_interior_splits() {
        let mut d = SequenceGapDetector::new();
        d.observe(10);
        d.observe(20);
        d.close_gap(15).unwrap();
        assert_eq!(
            d.gaps,
            vec![Gap { start: 11, end: 15 }, Gap { start: 16, end: 20 },]
        );
    }

    #[test]
    fn close_unknown_seq_rejected() {
        let mut d = SequenceGapDetector::new();
        d.observe(10);
        d.observe(13);
        assert!(matches!(
            d.close_gap(50).unwrap_err(),
            SeqError::GapNotFound
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut d = SequenceGapDetector::new();
        d.schema_version = "9.9.9".into();
        assert!(matches!(
            d.validate().unwrap_err(),
            SeqError::SchemaMismatch
        ));
    }

    #[test]
    fn detector_serde_roundtrip() {
        let mut d = SequenceGapDetector::new();
        d.observe(0);
        d.observe(5);
        let j = serde_json::to_string(&d).unwrap();
        let back: SequenceGapDetector = serde_json::from_str(&j).unwrap();
        assert_eq!(d, back);
    }
}
