//! `selfdef-text-canonical` — canonical text normalization.
//!
//! Options{lowercase, trim, collapse_whitespace,
//! strip_non_printable}. canonicalize(input) applies enabled
//! steps in fixed order. Deterministic; same input + opts →
//! same output.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Options.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Options {
    /// Lowercase (ASCII).
    pub lowercase: bool,
    /// Trim leading + trailing whitespace.
    pub trim: bool,
    /// Collapse runs of whitespace into single space.
    pub collapse_whitespace: bool,
    /// Strip non-printable ASCII chars.
    pub strip_non_printable: bool,
}

impl Options {
    /// New all-on.
    pub fn all() -> Self {
        Self {
            lowercase: true,
            trim: true,
            collapse_whitespace: true,
            strip_non_printable: true,
        }
    }
}

/// Versioned state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TextCanonical {
    /// Schema version.
    pub schema_version: String,
    /// Options.
    pub options: Options,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CanonError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

/// Apply.
pub fn canonicalize(input: &str, opts: Options) -> String {
    let mut s = input.to_string();
    if opts.strip_non_printable {
        s = s
            .chars()
            .filter(|c| !c.is_control() || *c == ' ' || *c == '\t' || *c == '\n')
            .collect();
    }
    if opts.lowercase {
        s = s.to_ascii_lowercase();
    }
    if opts.collapse_whitespace {
        let mut out = String::with_capacity(s.len());
        let mut last_ws = false;
        for c in s.chars() {
            if c.is_whitespace() {
                if !last_ws {
                    out.push(' ');
                }
                last_ws = true;
            } else {
                out.push(c);
                last_ws = false;
            }
        }
        s = out;
    }
    if opts.trim {
        s = s.trim().to_string();
    }
    s
}

impl TextCanonical {
    /// New.
    pub fn new(options: Options) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            options,
        }
    }

    /// Apply.
    pub fn apply(&self, input: &str) -> String {
        canonicalize(input, self.options)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CanonError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CanonError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_options() {
        let s = canonicalize("  Hello   World!  ", Options::all());
        assert_eq!(s, "hello world!");
    }

    #[test]
    fn no_options_passthrough() {
        let s = canonicalize(
            "  HI  ",
            Options {
                lowercase: false,
                trim: false,
                collapse_whitespace: false,
                strip_non_printable: false,
            },
        );
        assert_eq!(s, "  HI  ");
    }

    #[test]
    fn strip_non_printable() {
        let s = canonicalize(
            "hi\x07there",
            Options {
                lowercase: false,
                trim: false,
                collapse_whitespace: false,
                strip_non_printable: true,
            },
        );
        assert_eq!(s, "hithere");
    }

    #[test]
    fn collapse_only() {
        let s = canonicalize(
            "a   b\t\tc",
            Options {
                lowercase: false,
                trim: false,
                collapse_whitespace: true,
                strip_non_printable: false,
            },
        );
        assert_eq!(s, "a b c");
    }

    #[test]
    fn deterministic() {
        let opts = Options::all();
        assert_eq!(canonicalize("X", opts), canonicalize("X", opts));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = TextCanonical::new(Options::all());
        c.schema_version = "9.9.9".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            CanonError::SchemaMismatch
        ));
    }

    #[test]
    fn canonical_serde_roundtrip() {
        let c = TextCanonical::new(Options::all());
        let j = serde_json::to_string(&c).unwrap();
        let back: TextCanonical = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
