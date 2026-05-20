//! `selfdef-prompt-system-pinning` — pinned system-message ledger.
//!
//! `pin(id, body, priority)` records a pinned message; duplicate id
//! replaces. `unpin(id)` removes. `ordered()` returns the pinned set
//! in descending priority then ascending pin order, suitable for
//! context-assembly. The companion shrink policy treats these as
//! `Pinned` role and never drops or summarizes them.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One pinned entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pinned {
    /// Stable id.
    pub id: String,
    /// Body.
    pub body: String,
    /// Priority (higher = nearer the front).
    pub priority: u32,
    /// Monotonic pin-order seq.
    pub pin_seq: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromptSystemPinning {
    /// Schema version.
    pub schema_version: String,
    /// Max pinned at once.
    pub max_pinned: u32,
    /// id → entry.
    pub pins: BTreeMap<String, Pinned>,
    /// Next pin_seq.
    pub next_seq: u64,
}

/// Verdict for classify().
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PinVerdict {
    /// Pinned.
    Pinned {
        /// priority.
        priority: u32,
    },
    /// Not pinned.
    Unpinned,
}

/// Errors.
#[derive(Debug, Error)]
pub enum PinError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("id empty")]
    EmptyId,
    /// Empty body.
    #[error("body empty")]
    EmptyBody,
    /// Cap reached.
    #[error("max_pinned reached: {0}")]
    CapReached(u32),
}

impl PromptSystemPinning {
    /// New.
    pub fn new(max_pinned: u32) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            max_pinned,
            pins: BTreeMap::new(),
            next_seq: 1,
        }
    }

    /// Pin; replace-by-id semantics.
    pub fn pin(&mut self, id: &str, body: &str, priority: u32) -> Result<(), PinError> {
        if id.is_empty() { return Err(PinError::EmptyId); }
        if body.is_empty() { return Err(PinError::EmptyBody); }
        if !self.pins.contains_key(id) && self.pins.len() as u32 >= self.max_pinned {
            return Err(PinError::CapReached(self.max_pinned));
        }
        let pin_seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.pins.insert(id.into(), Pinned {
            id: id.into(),
            body: body.into(),
            priority,
            pin_seq,
        });
        Ok(())
    }

    /// Unpin.
    pub fn unpin(&mut self, id: &str) -> bool {
        self.pins.remove(id).is_some()
    }

    /// Classify.
    pub fn classify(&self, id: &str) -> PinVerdict {
        match self.pins.get(id) {
            Some(p) => PinVerdict::Pinned { priority: p.priority },
            None => PinVerdict::Unpinned,
        }
    }

    /// Ordered: priority desc, then pin_seq asc.
    pub fn ordered(&self) -> Vec<Pinned> {
        let mut v: Vec<Pinned> = self.pins.values().cloned().collect();
        v.sort_by(|a, b| b.priority.cmp(&a.priority).then(a.pin_seq.cmp(&b.pin_seq)));
        v
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), PinError> {
        if self.schema_version != SCHEMA_VERSION { return Err(PinError::SchemaMismatch); }
        if self.pins.len() as u32 > self.max_pinned {
            return Err(PinError::CapReached(self.max_pinned));
        }
        for (id, p) in &self.pins {
            if id.is_empty() { return Err(PinError::EmptyId); }
            if p.body.is_empty() { return Err(PinError::EmptyBody); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_and_classify() {
        let mut p = PromptSystemPinning::new(4);
        p.pin("ops", "always tell user X", 10).unwrap();
        assert_eq!(p.classify("ops"), PinVerdict::Pinned { priority: 10 });
        assert_eq!(p.classify("other"), PinVerdict::Unpinned);
    }

    #[test]
    fn unpin_clears() {
        let mut p = PromptSystemPinning::new(4);
        p.pin("ops", "x", 1).unwrap();
        assert!(p.unpin("ops"));
        assert_eq!(p.classify("ops"), PinVerdict::Unpinned);
    }

    #[test]
    fn replace_by_id() {
        let mut p = PromptSystemPinning::new(2);
        p.pin("ops", "old", 1).unwrap();
        p.pin("ops", "new", 5).unwrap();
        assert_eq!(p.pins.len(), 1);
        assert_eq!(p.pins["ops"].body, "new");
        assert_eq!(p.pins["ops"].priority, 5);
    }

    #[test]
    fn cap_reached() {
        let mut p = PromptSystemPinning::new(1);
        p.pin("a", "x", 1).unwrap();
        assert!(matches!(p.pin("b", "x", 1).unwrap_err(), PinError::CapReached(_)));
    }

    #[test]
    fn ordered_priority_desc() {
        let mut p = PromptSystemPinning::new(8);
        p.pin("low", "x", 1).unwrap();
        p.pin("high", "x", 100).unwrap();
        p.pin("mid", "x", 50).unwrap();
        let ids: Vec<_> = p.ordered().into_iter().map(|x| x.id).collect();
        assert_eq!(ids, vec!["high", "mid", "low"]);
    }

    #[test]
    fn ordered_tie_uses_pin_seq() {
        let mut p = PromptSystemPinning::new(8);
        p.pin("first", "x", 5).unwrap();
        p.pin("second", "x", 5).unwrap();
        let ids: Vec<_> = p.ordered().into_iter().map(|x| x.id).collect();
        assert_eq!(ids, vec!["first", "second"]);
    }

    #[test]
    fn empty_id_rejected() {
        let mut p = PromptSystemPinning::new(2);
        assert!(matches!(p.pin("", "x", 0).unwrap_err(), PinError::EmptyId));
    }

    #[test]
    fn empty_body_rejected() {
        let mut p = PromptSystemPinning::new(2);
        assert!(matches!(p.pin("a", "", 0).unwrap_err(), PinError::EmptyBody));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = PromptSystemPinning::new(2);
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), PinError::SchemaMismatch));
    }

    #[test]
    fn pinning_serde_roundtrip() {
        let mut p = PromptSystemPinning::new(2);
        p.pin("ops", "x", 5).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: PromptSystemPinning = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
