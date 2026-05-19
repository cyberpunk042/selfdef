//! `selfdef-input-canonicalization` — deterministic input normalizer.
//!
//! Sequence: strip BOM → drop zero-width → CRLF→LF → collapse
//! internal whitespace runs → trim. Records which Transforms ran.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Applied transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Transform {
    /// Removed UTF-8 BOM.
    BomStripped,
    /// Removed zero-width characters.
    ZeroWidthDropped,
    /// Normalized CRLF/CR to LF.
    LineEndingNormalized,
    /// Collapsed internal whitespace.
    WhitespaceCollapsed,
    /// Trimmed leading/trailing whitespace.
    Trimmed,
}

/// Result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanonResult {
    /// Schema version.
    pub schema_version: String,
    /// Canonical text.
    pub canonical: String,
    /// Transforms applied (order-sensitive).
    pub transforms: Vec<Transform>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CanonError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

/// Stateless canonicalizer.
#[derive(Debug, Clone, Default)]
pub struct InputCanonicalizer;

impl InputCanonicalizer {
    /// Canonicalize.
    pub fn canonicalize(input: &str) -> CanonResult {
        let mut transforms: Vec<Transform> = Vec::new();
        // 1. BOM strip.
        let after_bom = if let Some(stripped) = input.strip_prefix('\u{FEFF}') {
            transforms.push(Transform::BomStripped);
            stripped.to_string()
        } else {
            input.to_string()
        };
        // 2. Zero-width drop.
        let mut zw_seen = false;
        let no_zw: String = after_bom.chars().filter(|c| {
            let is_zw = matches!(*c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}');
            if is_zw { zw_seen = true; false } else { true }
        }).collect();
        if zw_seen { transforms.push(Transform::ZeroWidthDropped); }
        // 3. Line ending normalize.
        let mut line_norm = false;
        let normalized_lines: String = if no_zw.contains("\r\n") || no_zw.contains('\r') {
            line_norm = true;
            no_zw.replace("\r\n", "\n").replace('\r', "\n")
        } else {
            no_zw
        };
        if line_norm { transforms.push(Transform::LineEndingNormalized); }
        // 4. Collapse internal whitespace runs (≥2 spaces/tabs → single space; keep \n).
        let mut collapsed = String::with_capacity(normalized_lines.len());
        let mut last_was_space = false;
        let mut ws_collapsed_observed = false;
        for c in normalized_lines.chars() {
            let is_space_like = c == ' ' || c == '\t';
            if is_space_like {
                if last_was_space {
                    ws_collapsed_observed = true;
                    continue;
                }
                collapsed.push(' ');
                last_was_space = true;
            } else {
                collapsed.push(c);
                last_was_space = false;
            }
        }
        if ws_collapsed_observed { transforms.push(Transform::WhitespaceCollapsed); }
        // 5. Trim.
        let trimmed = collapsed.trim();
        if trimmed.len() != collapsed.len() {
            transforms.push(Transform::Trimmed);
        }
        CanonResult {
            schema_version: SCHEMA_VERSION.into(),
            canonical: trimmed.to_string(),
            transforms,
        }
    }
}

impl CanonResult {
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
    fn clean_unchanged() {
        let r = InputCanonicalizer::canonicalize("hello world");
        assert_eq!(r.canonical, "hello world");
        assert!(r.transforms.is_empty());
    }

    #[test]
    fn bom_stripped() {
        let r = InputCanonicalizer::canonicalize("\u{FEFF}hello");
        assert_eq!(r.canonical, "hello");
        assert!(r.transforms.contains(&Transform::BomStripped));
    }

    #[test]
    fn zero_width_dropped() {
        let r = InputCanonicalizer::canonicalize("hel\u{200B}lo");
        assert_eq!(r.canonical, "hello");
        assert!(r.transforms.contains(&Transform::ZeroWidthDropped));
    }

    #[test]
    fn crlf_to_lf() {
        let r = InputCanonicalizer::canonicalize("a\r\nb\r\nc");
        assert_eq!(r.canonical, "a\nb\nc");
        assert!(r.transforms.contains(&Transform::LineEndingNormalized));
    }

    #[test]
    fn whitespace_collapsed() {
        let r = InputCanonicalizer::canonicalize("hello    world");
        assert_eq!(r.canonical, "hello world");
        assert!(r.transforms.contains(&Transform::WhitespaceCollapsed));
    }

    #[test]
    fn trimmed() {
        let r = InputCanonicalizer::canonicalize("  hello  ");
        assert_eq!(r.canonical, "hello");
        assert!(r.transforms.contains(&Transform::Trimmed));
    }

    #[test]
    fn combined() {
        let r = InputCanonicalizer::canonicalize("\u{FEFF}  hello\r\n    world\u{200B}  ");
        assert_eq!(r.canonical, "hello\n world");
        // All transforms.
        for t in [
            Transform::BomStripped,
            Transform::ZeroWidthDropped,
            Transform::LineEndingNormalized,
            Transform::WhitespaceCollapsed,
            Transform::Trimmed,
        ] {
            assert!(r.transforms.contains(&t), "missing {t:?}");
        }
    }

    #[test]
    fn empty_passes() {
        let r = InputCanonicalizer::canonicalize("");
        assert_eq!(r.canonical, "");
        assert!(r.transforms.is_empty());
    }

    #[test]
    fn newline_preserved() {
        let r = InputCanonicalizer::canonicalize("a\nb");
        assert_eq!(r.canonical, "a\nb");
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = InputCanonicalizer::canonicalize("ok");
        r.schema_version = "9.9.9".into();
        assert!(matches!(r.validate().unwrap_err(), CanonError::SchemaMismatch));
    }

    #[test]
    fn transform_serde_kebab() {
        assert_eq!(serde_json::to_string(&Transform::BomStripped).unwrap(), "\"bom-stripped\"");
        assert_eq!(serde_json::to_string(&Transform::LineEndingNormalized).unwrap(), "\"line-ending-normalized\"");
    }

    #[test]
    fn result_serde_roundtrip() {
        let r = InputCanonicalizer::canonicalize("\u{FEFF}hello");
        let j = serde_json::to_string(&r).unwrap();
        let back: CanonResult = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
