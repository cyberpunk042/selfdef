//! `selfdef-edit-distance` — Levenshtein distance.
//!
//! distance(a, b) returns min single-char edits (insert,
//! delete, substitute) to transform a into b. O(|a|*|b|) time,
//! O(min(|a|,|b|)) space via two-row DP.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Versioned state placeholder.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EditDistanceState {
    /// Schema version.
    pub schema_version: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DistError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

/// Levenshtein distance between a and b.
pub fn distance(a: &str, b: &str) -> u32 {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() {
        return b.len() as u32;
    }
    if b.is_empty() {
        return a.len() as u32;
    }
    let (shorter, longer) = if a.len() <= b.len() {
        (&a, &b)
    } else {
        (&b, &a)
    };
    let n = shorter.len();
    let m = longer.len();
    let mut prev: Vec<u32> = (0..=n as u32).collect();
    let mut curr: Vec<u32> = vec![0; n + 1];
    for i in 1..=m {
        curr[0] = i as u32;
        for j in 1..=n {
            let cost = if longer[i - 1] == shorter[j - 1] {
                0
            } else {
                1
            };
            curr[j] = (curr[j - 1] + 1).min(prev[j] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

/// Similarity 0..=10000 (bp); 10000 = identical (or both empty).
pub fn similarity_bp(a: &str, b: &str) -> u32 {
    if a.is_empty() && b.is_empty() {
        return 10_000;
    }
    let max_len = a.chars().count().max(b.chars().count()) as u32;
    if max_len == 0 {
        return 10_000;
    }
    let d = distance(a, b);
    ((max_len.saturating_sub(d)) as u64 * 10_000 / max_len as u64) as u32
}

impl EditDistanceState {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DistError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(DistError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for EditDistanceState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_zero() {
        assert_eq!(distance("hello", "hello"), 0);
    }

    #[test]
    fn empty_string() {
        assert_eq!(distance("", "abc"), 3);
        assert_eq!(distance("abc", ""), 3);
    }

    #[test]
    fn known_kitten_sitting() {
        assert_eq!(distance("kitten", "sitting"), 3);
    }

    #[test]
    fn substitution() {
        assert_eq!(distance("cat", "bat"), 1);
    }

    #[test]
    fn unicode_chars() {
        assert_eq!(distance("café", "cafe"), 1);
    }

    #[test]
    fn similarity_identical() {
        assert_eq!(similarity_bp("abc", "abc"), 10_000);
        assert_eq!(similarity_bp("", ""), 10_000);
    }

    #[test]
    fn similarity_partial() {
        // kitten/sitting: max_len=7, d=3, sim=(7-3)/7*10000 = 5714.
        assert_eq!(similarity_bp("kitten", "sitting"), 5714);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = EditDistanceState::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            DistError::SchemaMismatch
        ));
    }

    #[test]
    fn state_serde_roundtrip() {
        let s = EditDistanceState::new();
        let j = serde_json::to_string(&s).unwrap();
        let back: EditDistanceState = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
