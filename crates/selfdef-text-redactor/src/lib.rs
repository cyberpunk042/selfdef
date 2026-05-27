//! `selfdef-text-redactor` — literal-pattern text redactor.
//!
//! `add_literal(needle)` registers a literal string to redact.
//! `redact(text)` returns `(redacted_text, replacement_count)`;
//! every occurrence of each registered needle is replaced with
//! `"[REDACTED:<original_char_count>]"`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TextRedactor {
    /// Schema version.
    pub schema_version: String,
    /// Registered needles.
    pub needles: BTreeSet<String>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RedactorError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty needle.
    #[error("needle empty")]
    EmptyNeedle,
}

impl TextRedactor {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            needles: BTreeSet::new(),
        }
    }

    /// Add a literal.
    pub fn add_literal(&mut self, needle: &str) -> Result<(), RedactorError> {
        if needle.is_empty() {
            return Err(RedactorError::EmptyNeedle);
        }
        self.needles.insert(needle.into());
        Ok(())
    }

    /// Redact. Returns (redacted, count).
    pub fn redact(&self, text: &str) -> (String, u32) {
        let mut out = text.to_string();
        let mut count = 0u32;
        // Longest-first so substring needles don't shadow superstrings.
        let mut needles: Vec<&str> = self.needles.iter().map(|s| s.as_str()).collect();
        needles.sort_by_key(|s| std::cmp::Reverse(s.len()));
        for n in needles {
            let token = format!("[REDACTED:{}]", n.chars().count());
            // Manual replace + count.
            let mut new = String::with_capacity(out.len());
            let mut start = 0;
            while let Some(idx) = out[start..].find(n) {
                let pos = start + idx;
                new.push_str(&out[start..pos]);
                new.push_str(&token);
                start = pos + n.len();
                count = count.saturating_add(1);
            }
            new.push_str(&out[start..]);
            out = new;
        }
        (out, count)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RedactorError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RedactorError::SchemaMismatch);
        }
        for n in &self.needles {
            if n.is_empty() {
                return Err(RedactorError::EmptyNeedle);
            }
        }
        Ok(())
    }
}

impl Default for TextRedactor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_replacement() {
        let mut r = TextRedactor::new();
        r.add_literal("secret").unwrap();
        let (out, n) = r.redact("a secret thing");
        assert_eq!(n, 1);
        assert_eq!(out, "a [REDACTED:6] thing");
    }

    #[test]
    fn multiple_occurrences() {
        let mut r = TextRedactor::new();
        r.add_literal("foo").unwrap();
        let (out, n) = r.redact("foo bar foo baz foo");
        assert_eq!(n, 3);
        assert!(out.starts_with("[REDACTED:3]"));
    }

    #[test]
    fn no_match() {
        let mut r = TextRedactor::new();
        r.add_literal("secret").unwrap();
        let (out, n) = r.redact("nothing here");
        assert_eq!(n, 0);
        assert_eq!(out, "nothing here");
    }

    #[test]
    fn longest_first() {
        let mut r = TextRedactor::new();
        r.add_literal("abc").unwrap();
        r.add_literal("abcdef").unwrap();
        let (out, _n) = r.redact("abcdef abc");
        assert!(out.contains("[REDACTED:6]"));
        assert!(out.contains("[REDACTED:3]"));
    }

    #[test]
    fn empty_needle_rejected() {
        let mut r = TextRedactor::new();
        assert!(matches!(
            r.add_literal("").unwrap_err(),
            RedactorError::EmptyNeedle
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = TextRedactor::new();
        r.schema_version = "9.9.9".into();
        assert!(matches!(
            r.validate().unwrap_err(),
            RedactorError::SchemaMismatch
        ));
    }

    #[test]
    fn redactor_serde_roundtrip() {
        let mut r = TextRedactor::new();
        r.add_literal("secret").unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: TextRedactor = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
