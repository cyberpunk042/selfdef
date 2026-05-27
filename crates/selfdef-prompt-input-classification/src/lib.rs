//! `selfdef-prompt-input-classification` — input-source trust class.
//!
//! Maps each InputSource to a TrustClass:
//! * Operator → Operator
//! * Tool / PriorOutput → Internal
//! * Web / Email / Document → Untrusted
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Source of an input chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InputSource {
    /// Operator typed it directly.
    Operator,
    /// Tool output (engine-controlled tool).
    Tool,
    /// Output of a prior LLM call.
    PriorOutput,
    /// Web fetch (URL, browser).
    Web,
    /// Email body / attachment.
    Email,
    /// External document the operator opened.
    Document,
}

/// Trust class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustClass {
    /// Operator-owned.
    Operator,
    /// Internal (tool output, prior LLM).
    Internal,
    /// Untrusted (web, email, doc).
    Untrusted,
}

/// Classified result.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Classification {
    /// Source.
    pub source: InputSource,
    /// Class.
    pub class: TrustClass,
}

/// Errors.
#[derive(Debug, Error)]
pub enum InputError {
    /// Schema drift (placeholder; serde version handled at envelope).
    #[error("schema version mismatch")]
    SchemaMismatch,
}

/// Stateless classifier.
#[derive(Debug, Clone, Default)]
pub struct PromptInputClassifier;

impl PromptInputClassifier {
    /// Map source → class.
    pub fn classify(source: InputSource) -> Classification {
        let class = match source {
            InputSource::Operator => TrustClass::Operator,
            InputSource::Tool | InputSource::PriorOutput => TrustClass::Internal,
            InputSource::Web | InputSource::Email | InputSource::Document => TrustClass::Untrusted,
        };
        Classification { source, class }
    }

    /// All InputSource variants (for table dumps).
    pub fn all_sources() -> &'static [InputSource] {
        const ALL: [InputSource; 6] = [
            InputSource::Operator,
            InputSource::Tool,
            InputSource::PriorOutput,
            InputSource::Web,
            InputSource::Email,
            InputSource::Document,
        ];
        &ALL
    }
}

/// Envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromptInputClassification {
    /// Schema version.
    pub schema_version: String,
}

impl PromptInputClassification {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), InputError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(InputError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for PromptInputClassification {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_is_operator() {
        let c = PromptInputClassifier::classify(InputSource::Operator);
        assert_eq!(c.class, TrustClass::Operator);
    }

    #[test]
    fn tool_is_internal() {
        let c = PromptInputClassifier::classify(InputSource::Tool);
        assert_eq!(c.class, TrustClass::Internal);
    }

    #[test]
    fn prior_output_is_internal() {
        let c = PromptInputClassifier::classify(InputSource::PriorOutput);
        assert_eq!(c.class, TrustClass::Internal);
    }

    #[test]
    fn web_is_untrusted() {
        let c = PromptInputClassifier::classify(InputSource::Web);
        assert_eq!(c.class, TrustClass::Untrusted);
    }

    #[test]
    fn email_is_untrusted() {
        let c = PromptInputClassifier::classify(InputSource::Email);
        assert_eq!(c.class, TrustClass::Untrusted);
    }

    #[test]
    fn document_is_untrusted() {
        let c = PromptInputClassifier::classify(InputSource::Document);
        assert_eq!(c.class, TrustClass::Untrusted);
    }

    #[test]
    fn all_sources_has_6() {
        assert_eq!(PromptInputClassifier::all_sources().len(), 6);
    }

    #[test]
    fn source_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&InputSource::PriorOutput).unwrap(),
            "\"prior-output\""
        );
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&TrustClass::Untrusted).unwrap(),
            "\"untrusted\""
        );
    }

    #[test]
    fn schema_drift_rejected() {
        let mut x = PromptInputClassification::new();
        x.schema_version = "9.9.9".into();
        assert!(matches!(
            x.validate().unwrap_err(),
            InputError::SchemaMismatch
        ));
    }

    #[test]
    fn classification_serde_roundtrip() {
        let c = PromptInputClassifier::classify(InputSource::Web);
        let j = serde_json::to_string(&c).unwrap();
        let back: Classification = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
