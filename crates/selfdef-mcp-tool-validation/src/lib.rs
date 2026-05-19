//! `selfdef-mcp-tool-validation` — MCP tool-descriptor validator.
//!
//! Validates a candidate ToolDescriptor before substrate registration:
//! * `name` matches `^[a-z][a-z0-9_-]{1,63}$`
//! * Schema version equals MCP_SCHEMA_VERSION.
//! * Parameter count ≤ MAX_PARAMETERS.
//! * Parameter names unique + non-empty.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// MCP descriptor schema version we accept.
pub const MCP_SCHEMA_VERSION: &str = "1.0.0";

/// Max parameter count.
pub const MAX_PARAMETERS: usize = 32;

/// One parameter declaration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolParameter {
    /// Stable name.
    pub name: String,
    /// Type label (free-form for now).
    pub r#type: String,
    /// Required?
    pub required: bool,
}

/// One descriptor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolDescriptor {
    /// Schema version of the descriptor itself.
    pub schema_version: String,
    /// Tool name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Parameters.
    pub parameters: Vec<ToolParameter>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ValidationError {
    /// Schema drift in descriptor.
    #[error("descriptor schema version {0} mismatch")]
    SchemaMismatch(String),
    /// Name doesn't match pattern.
    #[error("name {0:?} invalid (must match ^[a-z][a-z0-9_-]{{1,63}}$)")]
    BadName(String),
    /// Too many parameters.
    #[error("parameter count {0} > {1}")]
    TooManyParameters(usize, usize),
    /// Empty parameter name.
    #[error("parameter name empty")]
    EmptyParameterName,
    /// Duplicate parameter name.
    #[error("duplicate parameter name: {0}")]
    DuplicateParameterName(String),
    /// Empty type.
    #[error("parameter {0} type empty")]
    EmptyParameterType(String),
    /// Empty description.
    #[error("description empty")]
    EmptyDescription,
}

/// Stateless validator.
#[derive(Debug, Clone, Default)]
pub struct McpToolValidator;

impl McpToolValidator {
    /// Validate a candidate descriptor.
    pub fn validate(d: &ToolDescriptor) -> Result<(), ValidationError> {
        if d.schema_version != MCP_SCHEMA_VERSION {
            return Err(ValidationError::SchemaMismatch(d.schema_version.clone()));
        }
        if !valid_name(&d.name) {
            return Err(ValidationError::BadName(d.name.clone()));
        }
        if d.description.is_empty() {
            return Err(ValidationError::EmptyDescription);
        }
        if d.parameters.len() > MAX_PARAMETERS {
            return Err(ValidationError::TooManyParameters(d.parameters.len(), MAX_PARAMETERS));
        }
        use std::collections::HashSet;
        let mut seen: HashSet<&str> = HashSet::new();
        for p in &d.parameters {
            if p.name.is_empty() { return Err(ValidationError::EmptyParameterName); }
            if !seen.insert(p.name.as_str()) {
                return Err(ValidationError::DuplicateParameterName(p.name.clone()));
            }
            if p.r#type.is_empty() {
                return Err(ValidationError::EmptyParameterType(p.name.clone()));
            }
        }
        Ok(())
    }
}

fn valid_name(n: &str) -> bool {
    let len = n.len();
    if !(2..=64).contains(&len) { return false; }
    let bytes = n.as_bytes();
    if !bytes[0].is_ascii_lowercase() { return false; }
    bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(name: &str, desc: &str, params: Vec<ToolParameter>) -> ToolDescriptor {
        ToolDescriptor {
            schema_version: MCP_SCHEMA_VERSION.into(),
            name: name.into(),
            description: desc.into(),
            parameters: params,
        }
    }

    fn p(name: &str, ty: &str) -> ToolParameter {
        ToolParameter { name: name.into(), r#type: ty.into(), required: true }
    }

    #[test]
    fn ok_descriptor_passes() {
        let x = d("ls", "list files", vec![p("path", "string")]);
        McpToolValidator::validate(&x).unwrap();
    }

    #[test]
    fn bad_schema_rejected() {
        let mut x = d("ls", "list", vec![]);
        x.schema_version = "9.9.9".into();
        assert!(matches!(McpToolValidator::validate(&x).unwrap_err(), ValidationError::SchemaMismatch(_)));
    }

    #[test]
    fn bad_name_uppercase_rejected() {
        let x = d("Ls", "list", vec![]);
        assert!(matches!(McpToolValidator::validate(&x).unwrap_err(), ValidationError::BadName(_)));
    }

    #[test]
    fn bad_name_too_short_rejected() {
        let x = d("a", "list", vec![]);
        assert!(matches!(McpToolValidator::validate(&x).unwrap_err(), ValidationError::BadName(_)));
    }

    #[test]
    fn bad_name_too_long_rejected() {
        let x = d(&"a".repeat(65), "list", vec![]);
        assert!(matches!(McpToolValidator::validate(&x).unwrap_err(), ValidationError::BadName(_)));
    }

    #[test]
    fn bad_name_special_char_rejected() {
        let x = d("ls!", "list", vec![]);
        assert!(matches!(McpToolValidator::validate(&x).unwrap_err(), ValidationError::BadName(_)));
    }

    #[test]
    fn empty_description_rejected() {
        let x = d("ls", "", vec![]);
        assert!(matches!(McpToolValidator::validate(&x).unwrap_err(), ValidationError::EmptyDescription));
    }

    #[test]
    fn too_many_params_rejected() {
        let params: Vec<ToolParameter> = (0..40).map(|i| p(&format!("p{i}"), "string")).collect();
        let x = d("ls", "list", params);
        assert!(matches!(McpToolValidator::validate(&x).unwrap_err(), ValidationError::TooManyParameters(_, _)));
    }

    #[test]
    fn duplicate_param_rejected() {
        let x = d("ls", "list", vec![p("a", "s"), p("a", "s")]);
        assert!(matches!(McpToolValidator::validate(&x).unwrap_err(), ValidationError::DuplicateParameterName(_)));
    }

    #[test]
    fn empty_param_name_rejected() {
        let x = d("ls", "list", vec![p("", "s")]);
        assert!(matches!(McpToolValidator::validate(&x).unwrap_err(), ValidationError::EmptyParameterName));
    }

    #[test]
    fn empty_param_type_rejected() {
        let x = d("ls", "list", vec![p("a", "")]);
        assert!(matches!(McpToolValidator::validate(&x).unwrap_err(), ValidationError::EmptyParameterType(_)));
    }

    #[test]
    fn descriptor_serde_roundtrip() {
        let x = d("ls", "list", vec![p("path", "string")]);
        let j = serde_json::to_string(&x).unwrap();
        let back: ToolDescriptor = serde_json::from_str(&j).unwrap();
        assert_eq!(x, back);
    }
}
