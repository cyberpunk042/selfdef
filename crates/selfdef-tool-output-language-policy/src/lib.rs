//! `selfdef-tool-output-language-policy` — output shape gate.
//!
//! Each registered tool declares an expected output shape. check()
//! runs a cheap deterministic shape sanity check (e.g., Json must
//! start with `{` or `[`; Yaml first line must not start with `<` /
//! `{`). Returns Pass / ShapeMismatch.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Expected shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutputShape {
    /// JSON.
    Json,
    /// YAML.
    Yaml,
    /// Plain text.
    PlainText,
    /// S-expression.
    Sexpr,
    /// Markdown.
    Markdown,
}

/// Verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ShapeCheck {
    /// Passes shape check.
    Pass,
    /// Mismatch.
    ShapeMismatch {
        /// expected.
        expected: OutputShape,
        /// note.
        note: String,
    },
}

/// One tool registration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolShape {
    /// Tool id.
    pub tool_id: String,
    /// Expected shape.
    pub expected: OutputShape,
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolOutputLanguagePolicy {
    /// Schema version.
    pub schema_version: String,
    /// Registered tools.
    pub tools: Vec<ToolShape>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum LangError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("tool_id empty")]
    EmptyToolId,
    /// Duplicate.
    #[error("duplicate tool_id: {0}")]
    DuplicateToolId(String),
    /// Unknown.
    #[error("unknown tool_id: {0}")]
    Unknown(String),
}

impl ToolOutputLanguagePolicy {
    /// New empty.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            tools: Vec::new(),
        }
    }

    /// Register.
    pub fn register(&mut self, tool_id: &str, expected: OutputShape) -> Result<(), LangError> {
        if tool_id.is_empty() { return Err(LangError::EmptyToolId); }
        if self.tools.iter().any(|t| t.tool_id == tool_id) {
            return Err(LangError::DuplicateToolId(tool_id.into()));
        }
        self.tools.push(ToolShape { tool_id: tool_id.into(), expected });
        Ok(())
    }

    /// Check.
    pub fn check(&self, tool_id: &str, output: &str) -> Result<ShapeCheck, LangError> {
        let t = self.tools.iter().find(|t| t.tool_id == tool_id)
            .ok_or_else(|| LangError::Unknown(tool_id.into()))?;
        Ok(check_shape(t.expected, output))
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), LangError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(LangError::SchemaMismatch);
        }
        use std::collections::HashSet;
        let mut seen: HashSet<&str> = HashSet::new();
        for t in &self.tools {
            if t.tool_id.is_empty() { return Err(LangError::EmptyToolId); }
            if !seen.insert(t.tool_id.as_str()) {
                return Err(LangError::DuplicateToolId(t.tool_id.clone()));
            }
        }
        Ok(())
    }
}

fn check_shape(expected: OutputShape, output: &str) -> ShapeCheck {
    let trimmed = output.trim_start();
    match expected {
        OutputShape::Json => {
            if trimmed.starts_with('{') || trimmed.starts_with('[') {
                ShapeCheck::Pass
            } else {
                ShapeCheck::ShapeMismatch {
                    expected,
                    note: "json must start with { or [".into(),
                }
            }
        }
        OutputShape::Yaml => {
            if trimmed.starts_with('<') || trimmed.starts_with('{') {
                ShapeCheck::ShapeMismatch {
                    expected,
                    note: "yaml must not start with < or {".into(),
                }
            } else {
                ShapeCheck::Pass
            }
        }
        OutputShape::PlainText => ShapeCheck::Pass,
        OutputShape::Sexpr => {
            if trimmed.starts_with('(') {
                ShapeCheck::Pass
            } else {
                ShapeCheck::ShapeMismatch {
                    expected,
                    note: "sexpr must start with (".into(),
                }
            }
        }
        OutputShape::Markdown => {
            // Reject html-only output as markdown.
            if trimmed.starts_with("<!DOCTYPE") || trimmed.starts_with("<html") {
                ShapeCheck::ShapeMismatch {
                    expected,
                    note: "markdown should not start with html doctype".into(),
                }
            } else {
                ShapeCheck::Pass
            }
        }
    }
}

impl Default for ToolOutputLanguagePolicy {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_object_pass() {
        let mut p = ToolOutputLanguagePolicy::new();
        p.register("t", OutputShape::Json).unwrap();
        assert!(matches!(p.check("t", "{\"x\":1}").unwrap(), ShapeCheck::Pass));
    }

    #[test]
    fn json_array_pass() {
        let mut p = ToolOutputLanguagePolicy::new();
        p.register("t", OutputShape::Json).unwrap();
        assert!(matches!(p.check("t", "  [1,2,3]").unwrap(), ShapeCheck::Pass));
    }

    #[test]
    fn json_bad_rejected() {
        let mut p = ToolOutputLanguagePolicy::new();
        p.register("t", OutputShape::Json).unwrap();
        assert!(matches!(p.check("t", "hello").unwrap(), ShapeCheck::ShapeMismatch { .. }));
    }

    #[test]
    fn sexpr_pass() {
        let mut p = ToolOutputLanguagePolicy::new();
        p.register("t", OutputShape::Sexpr).unwrap();
        assert!(matches!(p.check("t", "(a b c)").unwrap(), ShapeCheck::Pass));
    }

    #[test]
    fn sexpr_bad_rejected() {
        let mut p = ToolOutputLanguagePolicy::new();
        p.register("t", OutputShape::Sexpr).unwrap();
        assert!(matches!(p.check("t", "[a b]").unwrap(), ShapeCheck::ShapeMismatch { .. }));
    }

    #[test]
    fn yaml_brace_rejected() {
        let mut p = ToolOutputLanguagePolicy::new();
        p.register("t", OutputShape::Yaml).unwrap();
        assert!(matches!(p.check("t", "{a: 1}").unwrap(), ShapeCheck::ShapeMismatch { .. }));
    }

    #[test]
    fn yaml_ok() {
        let mut p = ToolOutputLanguagePolicy::new();
        p.register("t", OutputShape::Yaml).unwrap();
        assert!(matches!(p.check("t", "a: 1\nb: 2").unwrap(), ShapeCheck::Pass));
    }

    #[test]
    fn plain_text_always_pass() {
        let mut p = ToolOutputLanguagePolicy::new();
        p.register("t", OutputShape::PlainText).unwrap();
        assert!(matches!(p.check("t", "anything goes").unwrap(), ShapeCheck::Pass));
    }

    #[test]
    fn markdown_html_doctype_rejected() {
        let mut p = ToolOutputLanguagePolicy::new();
        p.register("t", OutputShape::Markdown).unwrap();
        assert!(matches!(p.check("t", "<!DOCTYPE html><html>").unwrap(), ShapeCheck::ShapeMismatch { .. }));
    }

    #[test]
    fn unknown_tool_rejected() {
        let p = ToolOutputLanguagePolicy::new();
        assert!(matches!(p.check("none", "x").unwrap_err(), LangError::Unknown(_)));
    }

    #[test]
    fn duplicate_tool_rejected() {
        let mut p = ToolOutputLanguagePolicy::new();
        p.register("t", OutputShape::Json).unwrap();
        assert!(matches!(p.register("t", OutputShape::Yaml).unwrap_err(), LangError::DuplicateToolId(_)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = ToolOutputLanguagePolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), LangError::SchemaMismatch));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let mut p = ToolOutputLanguagePolicy::new();
        p.register("t", OutputShape::Json).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: ToolOutputLanguagePolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
