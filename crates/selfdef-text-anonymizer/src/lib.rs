//! `selfdef-text-anonymizer` — pattern-based PII masking.
//!
//! Each `Pattern { id, needle, placeholder }`. `anonymize(text)`
//! replaces every needle occurrence with `placeholder` and tallies
//! per-pattern hit counts. Pure substring matching — no regex.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One pattern.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pattern {
    /// Id.
    pub id: String,
    /// Needle.
    pub needle: String,
    /// Replacement placeholder (e.g. "[EMAIL]").
    pub placeholder: String,
    /// Hits observed.
    pub hits: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TextAnonymizer {
    /// Schema version.
    pub schema_version: String,
    /// id → pattern.
    pub patterns: BTreeMap<String, Pattern>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum AnonymizerError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("id empty")]
    EmptyId,
    /// Empty.
    #[error("needle empty")]
    EmptyNeedle,
    /// Empty.
    #[error("placeholder empty")]
    EmptyPlaceholder,
    /// Duplicate.
    #[error("duplicate pattern id: {0}")]
    DuplicateId(String),
}

impl TextAnonymizer {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            patterns: BTreeMap::new(),
        }
    }

    /// Register.
    pub fn register(&mut self, id: &str, needle: &str, placeholder: &str) -> Result<(), AnonymizerError> {
        if id.is_empty() { return Err(AnonymizerError::EmptyId); }
        if needle.is_empty() { return Err(AnonymizerError::EmptyNeedle); }
        if placeholder.is_empty() { return Err(AnonymizerError::EmptyPlaceholder); }
        if self.patterns.contains_key(id) {
            return Err(AnonymizerError::DuplicateId(id.into()));
        }
        self.patterns.insert(id.into(), Pattern {
            id: id.into(),
            needle: needle.into(),
            placeholder: placeholder.into(),
            hits: 0,
        });
        Ok(())
    }

    /// Pure anonymize (no state side-effect). Returns (output, hits_per_pattern).
    pub fn anonymize(&self, text: &str) -> (String, BTreeMap<String, u64>) {
        let mut out = text.to_string();
        let mut hits = BTreeMap::new();
        for p in self.patterns.values() {
            let count = out.matches(p.needle.as_str()).count() as u64;
            if count > 0 {
                out = out.replace(p.needle.as_str(), &p.placeholder);
                hits.insert(p.id.clone(), count);
            }
        }
        (out, hits)
    }

    /// Observe (anonymize + record hits in state).
    pub fn observe(&mut self, text: &str) -> String {
        let (out, hits) = self.anonymize(text);
        for (id, n) in hits {
            if let Some(p) = self.patterns.get_mut(&id) {
                p.hits = p.hits.saturating_add(n);
            }
        }
        out
    }

    /// Total hits across all patterns.
    pub fn total_hits(&self) -> u64 {
        self.patterns.values().map(|p| p.hits).fold(0u64, |a, b| a.saturating_add(b))
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), AnonymizerError> {
        if self.schema_version != SCHEMA_VERSION { return Err(AnonymizerError::SchemaMismatch); }
        for (id, p) in &self.patterns {
            if id.is_empty() { return Err(AnonymizerError::EmptyId); }
            if p.needle.is_empty() { return Err(AnonymizerError::EmptyNeedle); }
            if p.placeholder.is_empty() { return Err(AnonymizerError::EmptyPlaceholder); }
        }
        Ok(())
    }
}

impl Default for TextAnonymizer {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_single_pattern() {
        let mut t = TextAnonymizer::new();
        t.register("email", "alice@example.com", "[EMAIL]").unwrap();
        let (out, hits) = t.anonymize("contact alice@example.com today");
        assert_eq!(out, "contact [EMAIL] today");
        assert_eq!(hits["email"], 1);
    }

    #[test]
    fn multiple_occurrences() {
        let mut t = TextAnonymizer::new();
        t.register("foo", "FOO", "X").unwrap();
        let (out, hits) = t.anonymize("FOO and FOO and FOO");
        assert_eq!(out, "X and X and X");
        assert_eq!(hits["foo"], 3);
    }

    #[test]
    fn observe_records_hits() {
        let mut t = TextAnonymizer::new();
        t.register("foo", "FOO", "X").unwrap();
        t.observe("FOO FOO");
        t.observe("FOO");
        assert_eq!(t.patterns["foo"].hits, 3);
    }

    #[test]
    fn no_hits_unchanged() {
        let mut t = TextAnonymizer::new();
        t.register("foo", "FOO", "X").unwrap();
        let (out, hits) = t.anonymize("nothing here");
        assert_eq!(out, "nothing here");
        assert!(hits.is_empty());
    }

    #[test]
    fn duplicate_rejected() {
        let mut t = TextAnonymizer::new();
        t.register("p", "x", "y").unwrap();
        assert!(matches!(t.register("p", "x", "y").unwrap_err(), AnonymizerError::DuplicateId(_)));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut t = TextAnonymizer::new();
        assert!(matches!(t.register("", "n", "p").unwrap_err(), AnonymizerError::EmptyId));
        assert!(matches!(t.register("p", "", "p").unwrap_err(), AnonymizerError::EmptyNeedle));
        assert!(matches!(t.register("p", "n", "").unwrap_err(), AnonymizerError::EmptyPlaceholder));
    }

    #[test]
    fn total_hits_sums() {
        let mut t = TextAnonymizer::new();
        t.register("a", "A", "x").unwrap();
        t.register("b", "B", "y").unwrap();
        t.observe("AAB");
        assert_eq!(t.total_hits(), 3);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = TextAnonymizer::new();
        t.schema_version = "9.9.9".into();
        assert!(matches!(t.validate().unwrap_err(), AnonymizerError::SchemaMismatch));
    }

    #[test]
    fn anonymizer_serde_roundtrip() {
        let mut t = TextAnonymizer::new();
        t.register("p", "x", "X").unwrap();
        t.observe("xxx");
        let j = serde_json::to_string(&t).unwrap();
        let back: TextAnonymizer = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
