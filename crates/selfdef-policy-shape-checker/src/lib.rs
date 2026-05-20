//! `selfdef-policy-shape-checker` — structural validator for bundle metadata.
//!
//! `check(meta, max_field_len)` walks the supplied `BTreeMap<String,
//! String>`, verifies presence of `required_fields`, and emits the
//! list of missing-or-oversized issues. Pure validator; no semantic
//! reasoning about field values.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyShapeChecker {
    /// Schema version.
    pub schema_version: String,
    /// Required field names.
    pub required_fields: BTreeSet<String>,
    /// Max field value length in chars.
    pub max_field_len: u32,
}

/// Verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ShapeVerdict {
    /// All ok.
    Ok,
    /// Issues.
    Issues {
        /// Missing required fields.
        missing_fields: Vec<String>,
        /// Fields that exceeded max_field_len.
        oversized_fields: Vec<(String, u32)>,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum CheckerError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty required field.
    #[error("required field name empty")]
    EmptyRequiredField,
    /// max_field_len zero.
    #[error("max_field_len must be > 0")]
    MaxFieldLenZero,
}

impl PolicyShapeChecker {
    /// New.
    pub fn new(required_fields: BTreeSet<String>, max_field_len: u32) -> Result<Self, CheckerError> {
        if max_field_len == 0 { return Err(CheckerError::MaxFieldLenZero); }
        for r in &required_fields {
            if r.is_empty() { return Err(CheckerError::EmptyRequiredField); }
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            required_fields,
            max_field_len,
        })
    }

    /// Check.
    pub fn check(&self, meta: &BTreeMap<String, String>) -> ShapeVerdict {
        let mut missing = Vec::new();
        let mut oversized = Vec::new();
        for req in &self.required_fields {
            if !meta.contains_key(req) {
                missing.push(req.clone());
            }
        }
        for (k, v) in meta {
            let len = v.chars().count() as u32;
            if len > self.max_field_len {
                oversized.push((k.clone(), len));
            }
        }
        if missing.is_empty() && oversized.is_empty() {
            ShapeVerdict::Ok
        } else {
            ShapeVerdict::Issues { missing_fields: missing, oversized_fields: oversized }
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CheckerError> {
        if self.schema_version != SCHEMA_VERSION { return Err(CheckerError::SchemaMismatch); }
        if self.max_field_len == 0 { return Err(CheckerError::MaxFieldLenZero); }
        for r in &self.required_fields {
            if r.is_empty() { return Err(CheckerError::EmptyRequiredField); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checker() -> PolicyShapeChecker {
        let mut req = BTreeSet::new();
        req.insert("policy_id".into());
        req.insert("version".into());
        req.insert("signature".into());
        PolicyShapeChecker::new(req, 256).unwrap()
    }

    #[test]
    fn empty_required_field_rejected() {
        let mut req = BTreeSet::new();
        req.insert("".into());
        assert!(matches!(PolicyShapeChecker::new(req, 256).unwrap_err(), CheckerError::EmptyRequiredField));
    }

    #[test]
    fn max_field_zero_rejected() {
        assert!(matches!(PolicyShapeChecker::new(BTreeSet::new(), 0).unwrap_err(), CheckerError::MaxFieldLenZero));
    }

    #[test]
    fn ok_when_all_present_and_sized() {
        let c = checker();
        let mut meta = BTreeMap::new();
        meta.insert("policy_id".into(), "p1".into());
        meta.insert("version".into(), "1.0.0".into());
        meta.insert("signature".into(), "ABC".into());
        assert_eq!(c.check(&meta), ShapeVerdict::Ok);
    }

    #[test]
    fn missing_fields_reported() {
        let c = checker();
        let mut meta = BTreeMap::new();
        meta.insert("policy_id".into(), "p1".into());
        match c.check(&meta) {
            ShapeVerdict::Issues { missing_fields, oversized_fields } => {
                assert!(missing_fields.contains(&"version".into()));
                assert!(missing_fields.contains(&"signature".into()));
                assert!(oversized_fields.is_empty());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn oversized_fields_reported() {
        let c = checker();
        let mut meta = BTreeMap::new();
        meta.insert("policy_id".into(), "p1".into());
        meta.insert("version".into(), "1.0.0".into());
        meta.insert("signature".into(), "A".repeat(500));
        match c.check(&meta) {
            ShapeVerdict::Issues { oversized_fields, .. } => {
                assert_eq!(oversized_fields[0].0, "signature");
                assert_eq!(oversized_fields[0].1, 500);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = checker();
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), CheckerError::SchemaMismatch));
    }

    #[test]
    fn shape_serde_roundtrip() {
        let c = checker();
        let j = serde_json::to_string(&c).unwrap();
        let back: PolicyShapeChecker = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
