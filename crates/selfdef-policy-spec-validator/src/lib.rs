//! `selfdef-policy-spec-validator` — declarative spec validator.
//!
//! Each Spec has required_fields[] + forbidden_fields[] + a name.
//! validate(spec, present_fields) returns Ok or Vec<Issue> listing
//! missing required + present forbidden.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One spec.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Spec {
    /// Name.
    pub name: String,
    /// Required fields.
    pub required: BTreeSet<String>,
    /// Forbidden fields.
    pub forbidden: BTreeSet<String>,
}

/// One issue.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Issue {
    /// Missing required.
    MissingRequired {
        /// field.
        field: String,
    },
    /// Forbidden present.
    ForbiddenPresent {
        /// field.
        field: String,
    },
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicySpecValidator {
    /// Schema version.
    pub schema_version: String,
    /// name → spec.
    pub specs: BTreeMap<String, Spec>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SpecError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("name empty")]
    EmptyName,
    /// Empty.
    #[error("field empty")]
    EmptyField,
    /// Duplicate.
    #[error("duplicate spec: {0}")]
    DuplicateSpec(String),
    /// Unknown.
    #[error("unknown spec: {0}")]
    UnknownSpec(String),
}

impl PolicySpecValidator {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            specs: BTreeMap::new(),
        }
    }

    /// Register.
    pub fn register(
        &mut self,
        name: &str,
        required: &[&str],
        forbidden: &[&str],
    ) -> Result<(), SpecError> {
        if name.is_empty() {
            return Err(SpecError::EmptyName);
        }
        if self.specs.contains_key(name) {
            return Err(SpecError::DuplicateSpec(name.into()));
        }
        let mut req = BTreeSet::new();
        for f in required {
            if f.is_empty() {
                return Err(SpecError::EmptyField);
            }
            req.insert((*f).into());
        }
        let mut fb = BTreeSet::new();
        for f in forbidden {
            if f.is_empty() {
                return Err(SpecError::EmptyField);
            }
            fb.insert((*f).into());
        }
        self.specs.insert(
            name.into(),
            Spec {
                name: name.into(),
                required: req,
                forbidden: fb,
            },
        );
        Ok(())
    }

    /// Validate.
    pub fn check(&self, name: &str, present: &[&str]) -> Result<Vec<Issue>, SpecError> {
        let s = self
            .specs
            .get(name)
            .ok_or_else(|| SpecError::UnknownSpec(name.into()))?;
        let present_set: BTreeSet<String> = present.iter().map(|f| (*f).into()).collect();
        let mut issues = Vec::new();
        for r in &s.required {
            if !present_set.contains(r) {
                issues.push(Issue::MissingRequired { field: r.clone() });
            }
        }
        for f in &s.forbidden {
            if present_set.contains(f) {
                issues.push(Issue::ForbiddenPresent { field: f.clone() });
            }
        }
        Ok(issues)
    }

    /// Validate state.
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SpecError::SchemaMismatch);
        }
        for (n, s) in &self.specs {
            if n.is_empty() {
                return Err(SpecError::EmptyName);
            }
            for f in s.required.iter().chain(s.forbidden.iter()) {
                if f.is_empty() {
                    return Err(SpecError::EmptyField);
                }
            }
        }
        Ok(())
    }
}

impl Default for PolicySpecValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_required_present_ok() {
        let mut v = PolicySpecValidator::new();
        v.register("p", &["name", "scope"], &[]).unwrap();
        assert!(v.check("p", &["name", "scope"]).unwrap().is_empty());
    }

    #[test]
    fn missing_required_flagged() {
        let mut v = PolicySpecValidator::new();
        v.register("p", &["name", "scope"], &[]).unwrap();
        let issues = v.check("p", &["name"]).unwrap();
        assert_eq!(issues.len(), 1);
        match &issues[0] {
            Issue::MissingRequired { field } => assert_eq!(field, "scope"),
            _ => panic!(),
        }
    }

    #[test]
    fn forbidden_present_flagged() {
        let mut v = PolicySpecValidator::new();
        v.register("p", &[], &["secret"]).unwrap();
        let issues = v.check("p", &["name", "secret"]).unwrap();
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn unknown_spec_rejected() {
        let v = PolicySpecValidator::new();
        assert!(matches!(
            v.check("nope", &[]).unwrap_err(),
            SpecError::UnknownSpec(_)
        ));
    }

    #[test]
    fn duplicate_spec_rejected() {
        let mut v = PolicySpecValidator::new();
        v.register("p", &[], &[]).unwrap();
        assert!(matches!(
            v.register("p", &[], &[]).unwrap_err(),
            SpecError::DuplicateSpec(_)
        ));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut v = PolicySpecValidator::new();
        assert!(matches!(
            v.register("", &[], &[]).unwrap_err(),
            SpecError::EmptyName
        ));
        assert!(matches!(
            v.register("p", &[""], &[]).unwrap_err(),
            SpecError::EmptyField
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut v = PolicySpecValidator::new();
        v.schema_version = "9.9.9".into();
        assert!(matches!(
            v.validate().unwrap_err(),
            SpecError::SchemaMismatch
        ));
    }

    #[test]
    fn validator_serde_roundtrip() {
        let mut v = PolicySpecValidator::new();
        v.register("p", &["a"], &["b"]).unwrap();
        let j = serde_json::to_string(&v).unwrap();
        let back: PolicySpecValidator = serde_json::from_str(&j).unwrap();
        assert_eq!(v, back);
    }
}
