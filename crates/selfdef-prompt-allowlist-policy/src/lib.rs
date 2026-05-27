//! `selfdef-prompt-allowlist-policy` — registered-template gate.
//!
//! No implicit prompts: every LLM call must reference a registered
//! template_id. The template declares (version, expected_param_names).
//! admit(id, supplied_params) returns Allow / Unknown / MissingParams.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One registered template.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromptTemplate {
    /// Stable id.
    pub id: String,
    /// Semantic version.
    pub version: String,
    /// Expected parameter names.
    pub params: Vec<String>,
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromptAllowlistPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Registered templates.
    pub templates: Vec<PromptTemplate>,
}

/// Decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AdmitDecision {
    /// Allowed.
    Allow,
    /// Template id not registered.
    Unknown,
    /// Required params missing.
    MissingParams {
        /// missing names.
        missing: Vec<String>,
    },
    /// Extra params not declared.
    UnexpectedParams {
        /// extra names.
        extra: Vec<String>,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum AllowlistError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("template id empty")]
    EmptyId,
    /// Empty version.
    #[error("template {0} version empty")]
    EmptyVersion(String),
    /// Empty param name.
    #[error("template {0} param name empty")]
    EmptyParamName(String),
    /// Duplicate id.
    #[error("duplicate template id: {0}")]
    DuplicateId(String),
    /// Duplicate param in template.
    #[error("template {0} has duplicate param: {1}")]
    DuplicateParam(String, String),
}

impl PromptAllowlistPolicy {
    /// New empty.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            templates: Vec::new(),
        }
    }

    /// Register.
    pub fn register(&mut self, t: PromptTemplate) -> Result<(), AllowlistError> {
        check_template(&t)?;
        if self.templates.iter().any(|x| x.id == t.id) {
            return Err(AllowlistError::DuplicateId(t.id));
        }
        self.templates.push(t);
        Ok(())
    }

    /// Admit.
    pub fn admit(&self, id: &str, supplied: &[String]) -> AdmitDecision {
        let t = match self.templates.iter().find(|t| t.id == id) {
            Some(t) => t,
            None => return AdmitDecision::Unknown,
        };
        use std::collections::HashSet;
        let supplied_set: HashSet<&str> = supplied.iter().map(String::as_str).collect();
        let declared_set: HashSet<&str> = t.params.iter().map(String::as_str).collect();
        let missing: Vec<String> = declared_set
            .difference(&supplied_set)
            .map(|s| (*s).to_string())
            .collect();
        if !missing.is_empty() {
            let mut m = missing;
            m.sort();
            return AdmitDecision::MissingParams { missing: m };
        }
        let extra: Vec<String> = supplied_set
            .difference(&declared_set)
            .map(|s| (*s).to_string())
            .collect();
        if !extra.is_empty() {
            let mut e = extra;
            e.sort();
            return AdmitDecision::UnexpectedParams { extra: e };
        }
        AdmitDecision::Allow
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), AllowlistError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(AllowlistError::SchemaMismatch);
        }
        use std::collections::HashSet;
        let mut ids: HashSet<&str> = HashSet::new();
        for t in &self.templates {
            check_template(t)?;
            if !ids.insert(t.id.as_str()) {
                return Err(AllowlistError::DuplicateId(t.id.clone()));
            }
        }
        Ok(())
    }
}

fn check_template(t: &PromptTemplate) -> Result<(), AllowlistError> {
    if t.id.is_empty() {
        return Err(AllowlistError::EmptyId);
    }
    if t.version.is_empty() {
        return Err(AllowlistError::EmptyVersion(t.id.clone()));
    }
    use std::collections::HashSet;
    let mut seen: HashSet<&str> = HashSet::new();
    for p in &t.params {
        if p.is_empty() {
            return Err(AllowlistError::EmptyParamName(t.id.clone()));
        }
        if !seen.insert(p.as_str()) {
            return Err(AllowlistError::DuplicateParam(t.id.clone(), p.clone()));
        }
    }
    Ok(())
}

impl Default for PromptAllowlistPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpl(id: &str, params: &[&str]) -> PromptTemplate {
        PromptTemplate {
            id: id.into(),
            version: "1.0.0".into(),
            params: params.iter().map(|s| (*s).into()).collect(),
        }
    }

    #[test]
    fn unknown_id_rejected() {
        let p = PromptAllowlistPolicy::new();
        assert!(matches!(p.admit("none", &[]), AdmitDecision::Unknown));
    }

    #[test]
    fn matching_params_allow() {
        let mut p = PromptAllowlistPolicy::new();
        p.register(tmpl("hello", &["name", "lang"])).unwrap();
        let supplied = vec!["name".into(), "lang".into()];
        assert!(matches!(p.admit("hello", &supplied), AdmitDecision::Allow));
    }

    #[test]
    fn missing_params_reported() {
        let mut p = PromptAllowlistPolicy::new();
        p.register(tmpl("hello", &["name", "lang"])).unwrap();
        let supplied = vec!["name".into()];
        match p.admit("hello", &supplied) {
            AdmitDecision::MissingParams { missing } => assert_eq!(missing, vec!["lang"]),
            _ => panic!(),
        }
    }

    #[test]
    fn extra_params_reported() {
        let mut p = PromptAllowlistPolicy::new();
        p.register(tmpl("hello", &["name"])).unwrap();
        let supplied = vec!["name".into(), "extra".into()];
        match p.admit("hello", &supplied) {
            AdmitDecision::UnexpectedParams { extra } => assert_eq!(extra, vec!["extra"]),
            _ => panic!(),
        }
    }

    #[test]
    fn duplicate_template_rejected() {
        let mut p = PromptAllowlistPolicy::new();
        p.register(tmpl("a", &[])).unwrap();
        assert!(matches!(
            p.register(tmpl("a", &[])).unwrap_err(),
            AllowlistError::DuplicateId(_)
        ));
    }

    #[test]
    fn empty_id_rejected() {
        let mut p = PromptAllowlistPolicy::new();
        assert!(matches!(
            p.register(tmpl("", &[])).unwrap_err(),
            AllowlistError::EmptyId
        ));
    }

    #[test]
    fn empty_version_rejected() {
        let mut p = PromptAllowlistPolicy::new();
        let mut t = tmpl("a", &[]);
        t.version = String::new();
        assert!(matches!(
            p.register(t).unwrap_err(),
            AllowlistError::EmptyVersion(_)
        ));
    }

    #[test]
    fn empty_param_rejected() {
        let mut p = PromptAllowlistPolicy::new();
        assert!(matches!(
            p.register(tmpl("a", &[""])).unwrap_err(),
            AllowlistError::EmptyParamName(_)
        ));
    }

    #[test]
    fn duplicate_param_rejected() {
        let mut p = PromptAllowlistPolicy::new();
        assert!(matches!(
            p.register(tmpl("a", &["x", "x"])).unwrap_err(),
            AllowlistError::DuplicateParam(_, _)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = PromptAllowlistPolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            AllowlistError::SchemaMismatch
        ));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let mut p = PromptAllowlistPolicy::new();
        p.register(tmpl("hello", &["name"])).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: PromptAllowlistPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
