//! `selfdef-duplicate-detect` — near-duplicate text detection.
//!
//! observe(id, text) records text + k-shingle set (k=3 chars).
//! is_near_dup(text, threshold_bp) checks against all recorded
//! entries; Jaccard similarity (intersection/union of shingles)
//! in bp; returns Some(id) on >= threshold else None.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DupEntry {
    /// Stored text.
    pub text: String,
    /// Shingle set (sorted).
    pub shingles: BTreeSet<String>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DuplicateDetect {
    /// Schema version.
    pub schema_version: String,
    /// id → entry.
    pub entries: BTreeMap<String, DupEntry>,
    /// k (shingle width).
    pub k: u32,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DupError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("id empty")]
    EmptyId,
    /// Empty.
    #[error("text empty")]
    EmptyText,
    /// Bad k.
    #[error("k must be >= 1")]
    BadK,
    /// Duplicate.
    #[error("duplicate id: {0}")]
    DuplicateId(String),
}

fn shingles(text: &str, k: u32) -> BTreeSet<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = BTreeSet::new();
    let k = k as usize;
    if chars.len() < k { return out; }
    for i in 0..=(chars.len() - k) {
        let sh: String = chars[i..i + k].iter().collect();
        out.insert(sh);
    }
    out
}

fn jaccard_bp(a: &BTreeSet<String>, b: &BTreeSet<String>) -> u32 {
    if a.is_empty() && b.is_empty() { return 10_000; }
    let inter = a.intersection(b).count();
    let union = a.union(b).count();
    if union == 0 { return 0; }
    ((inter as u64 * 10_000) / union as u64) as u32
}

impl DuplicateDetect {
    /// New.
    pub fn new(k: u32) -> Result<Self, DupError> {
        if k == 0 { return Err(DupError::BadK); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            entries: BTreeMap::new(),
            k,
        })
    }

    /// Record.
    pub fn observe(&mut self, id: &str, text: &str) -> Result<(), DupError> {
        if id.is_empty() { return Err(DupError::EmptyId); }
        if text.is_empty() { return Err(DupError::EmptyText); }
        if self.entries.contains_key(id) {
            return Err(DupError::DuplicateId(id.into()));
        }
        let sh = shingles(text, self.k);
        self.entries.insert(id.into(), DupEntry {
            text: text.into(),
            shingles: sh,
        });
        Ok(())
    }

    /// Check; returns first id where similarity >= threshold_bp.
    pub fn is_near_dup(&self, text: &str, threshold_bp: u32) -> Option<&str> {
        let sh = shingles(text, self.k);
        for (id, e) in &self.entries {
            if jaccard_bp(&sh, &e.shingles) >= threshold_bp {
                return Some(id.as_str());
            }
        }
        None
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DupError> {
        if self.schema_version != SCHEMA_VERSION { return Err(DupError::SchemaMismatch); }
        if self.k == 0 { return Err(DupError::BadK); }
        for (id, e) in &self.entries {
            if id.is_empty() { return Err(DupError::EmptyId); }
            if e.text.is_empty() { return Err(DupError::EmptyText); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_high_jaccard() {
        let mut d = DuplicateDetect::new(3).unwrap();
        d.observe("a", "the quick brown fox").unwrap();
        let r = d.is_near_dup("the quick brown fox", 9000);
        assert_eq!(r, Some("a"));
    }

    #[test]
    fn no_match_for_disjoint() {
        let mut d = DuplicateDetect::new(3).unwrap();
        d.observe("a", "the quick brown fox").unwrap();
        let r = d.is_near_dup("xyz pdq abc", 5000);
        assert!(r.is_none());
    }

    #[test]
    fn partial_match() {
        let mut d = DuplicateDetect::new(3).unwrap();
        d.observe("a", "the quick brown fox").unwrap();
        // Mostly same → matches at moderate threshold.
        let r = d.is_near_dup("the quick brown dog", 5000);
        assert_eq!(r, Some("a"));
    }

    #[test]
    fn duplicate_id_rejected() {
        let mut d = DuplicateDetect::new(3).unwrap();
        d.observe("a", "x").unwrap();
        assert!(matches!(d.observe("a", "y").unwrap_err(), DupError::DuplicateId(_)));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut d = DuplicateDetect::new(3).unwrap();
        assert!(matches!(d.observe("", "x").unwrap_err(), DupError::EmptyId));
        assert!(matches!(d.observe("i", "").unwrap_err(), DupError::EmptyText));
        assert!(matches!(DuplicateDetect::new(0).unwrap_err(), DupError::BadK));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut d = DuplicateDetect::new(3).unwrap();
        d.schema_version = "9.9.9".into();
        assert!(matches!(d.validate().unwrap_err(), DupError::SchemaMismatch));
    }

    #[test]
    fn detector_serde_roundtrip() {
        let mut d = DuplicateDetect::new(3).unwrap();
        d.observe("a", "x").unwrap();
        let j = serde_json::to_string(&d).unwrap();
        let back: DuplicateDetect = serde_json::from_str(&j).unwrap();
        assert_eq!(d, back);
    }
}
