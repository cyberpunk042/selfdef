//! `selfdef-prompt-output-watermark` — invisible-mark embedder.
//!
//! Embeds an 8-bit-per-char binary watermark using zero-width
//! characters interleaved with the text:
//! * 0 bit → ZWSP (U+200B)
//! * 1 bit → ZWNJ (U+200C)
//!
//! Watermark is the 8 lower bits of an FNV-1a hash of the
//! decision_id. verify(text) attempts to recover the byte.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

const ZWSP: char = '\u{200B}';
const ZWNJ: char = '\u{200C}';

/// Result of embedding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmbedResult {
    /// Schema version.
    pub schema_version: String,
    /// Watermarked text.
    pub watermarked: String,
    /// Watermark byte (the marker that was embedded).
    pub mark: u8,
}

/// Verification result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum VerifyResult {
    /// Watermark recovered.
    Found {
        /// recovered byte.
        mark: u8,
    },
    /// No watermark bits present.
    NotFound,
}

/// Errors.
#[derive(Debug, Error)]
pub enum WatermarkError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Text too short to embed a byte.
    #[error("text length {0} too short to embed 8 bits")]
    TextTooShort(usize),
}

/// Embedder.
#[derive(Debug, Clone, Default)]
pub struct OutputWatermark;

impl OutputWatermark {
    /// Compute the 8-bit mark from a decision_id (lower byte of FNV-1a).
    pub fn mark_for(decision_id: &str) -> u8 {
        let mut h: u64 = 0xcbf29ce484222325;
        for b in decision_id.bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        (h & 0xff) as u8
    }

    /// Embed.
    pub fn embed(decision_id: &str, text: &str) -> Result<EmbedResult, WatermarkError> {
        let mark = Self::mark_for(decision_id);
        let chars: Vec<char> = text.chars().collect();
        if chars.len() < 8 {
            return Err(WatermarkError::TextTooShort(chars.len()));
        }
        // Interleave a ZW char after each of the first 8 chars.
        let mut out = String::with_capacity(text.len() + 24);
        for (i, c) in chars.iter().enumerate() {
            out.push(*c);
            if i < 8 {
                let bit = (mark >> (7 - i)) & 1;
                out.push(if bit == 1 { ZWNJ } else { ZWSP });
            }
        }
        Ok(EmbedResult {
            schema_version: SCHEMA_VERSION.into(),
            watermarked: out,
            mark,
        })
    }

    /// Verify (recover the 8-bit mark).
    pub fn verify(text: &str) -> VerifyResult {
        let mut bits: Vec<u8> = Vec::new();
        for c in text.chars() {
            match c {
                ZWSP => bits.push(0),
                ZWNJ => bits.push(1),
                _ => {}
            }
            if bits.len() == 8 {
                break;
            }
        }
        if bits.len() < 8 {
            return VerifyResult::NotFound;
        }
        let mut mark = 0u8;
        for (i, &b) in bits.iter().enumerate() {
            mark |= b << (7 - i);
        }
        VerifyResult::Found { mark }
    }
}

impl EmbedResult {
    /// Validate.
    pub fn validate(&self) -> Result<(), WatermarkError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(WatermarkError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_deterministic_per_id() {
        let a = OutputWatermark::mark_for("decision-42");
        let b = OutputWatermark::mark_for("decision-42");
        assert_eq!(a, b);
    }

    #[test]
    fn mark_differs_per_id() {
        let a = OutputWatermark::mark_for("decision-1");
        let b = OutputWatermark::mark_for("decision-2");
        // Different inputs almost always produce different bytes.
        assert_ne!(a, b);
    }

    #[test]
    fn embed_roundtrip() {
        let r = OutputWatermark::embed("decision-42", "hello world").unwrap();
        let v = OutputWatermark::verify(&r.watermarked);
        match v {
            VerifyResult::Found { mark } => assert_eq!(mark, r.mark),
            _ => panic!(),
        }
    }

    #[test]
    fn empty_text_rejected() {
        assert!(matches!(
            OutputWatermark::embed("d", "hi").unwrap_err(),
            WatermarkError::TextTooShort(2)
        ));
    }

    #[test]
    fn no_watermark_returns_not_found() {
        let v = OutputWatermark::verify("plain text");
        assert!(matches!(v, VerifyResult::NotFound));
    }

    #[test]
    fn watermarked_visually_unchanged_to_naive_reader() {
        // The visible chars (after stripping ZWSP/ZWNJ) match the original
        // for the prefix where bits were embedded.
        let original = "this is a test sentence with enough room";
        let r = OutputWatermark::embed("d", original).unwrap();
        let stripped: String = r
            .watermarked
            .chars()
            .filter(|c| !matches!(c, '\u{200B}' | '\u{200C}'))
            .collect();
        assert_eq!(stripped, original);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = OutputWatermark::embed("d", "hello world").unwrap();
        r.schema_version = "9.9.9".into();
        assert!(matches!(
            r.validate().unwrap_err(),
            WatermarkError::SchemaMismatch
        ));
    }

    #[test]
    fn result_serde_kebab() {
        let v = VerifyResult::NotFound;
        assert!(
            serde_json::to_string(&v)
                .unwrap()
                .contains("\"kind\":\"not-found\"")
        );
    }

    #[test]
    fn embed_result_serde_roundtrip() {
        let r = OutputWatermark::embed("d", "hello world").unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: EmbedResult = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
