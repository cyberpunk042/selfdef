//! `selfdef-tool-arg-redaction-policy` — redact sensitive tool-call args.
//!
//! Patterns:
//!   * exact match: `password` matches `password` only.
//!   * suffix glob: `*_token` matches any name ending with `_token`.
//!   * prefix glob: `aws_*` matches any name starting with `aws_`.
//!   * full wildcard `*` matches all names.
//!
//! Match is case-insensitive. `redact_args(args)` returns a new
//! `Vec<(name, value)>` where matching entries' values become
//! `"[REDACTED:<len>]"` with the original length recorded for audit.
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
pub struct ToolArgRedactionPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Patterns.
    pub patterns: BTreeSet<String>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RedactError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty pattern.
    #[error("empty pattern")]
    EmptyPattern,
}

impl ToolArgRedactionPolicy {
    /// Canonical (common sensitive arg names).
    pub fn canonical() -> Self {
        let mut p = BTreeSet::new();
        for name in [
            "password", "passwd", "secret", "api_key", "apikey", "access_key",
            "auth", "authorization", "bearer", "credential", "credentials",
            "private_key", "ssh_key", "session", "session_id",
            "*_token", "*_secret", "*_key", "aws_*", "gcp_*", "azure_*",
        ] {
            p.insert(name.into());
        }
        Self {
            schema_version: SCHEMA_VERSION.into(),
            patterns: p,
        }
    }

    /// Add a pattern.
    pub fn add(&mut self, pat: &str) -> Result<(), RedactError> {
        if pat.is_empty() { return Err(RedactError::EmptyPattern); }
        self.patterns.insert(pat.into());
        Ok(())
    }

    fn matches(&self, name: &str) -> Option<String> {
        let n = name.to_lowercase();
        for pat in &self.patterns {
            if pat == "*" { return Some(pat.clone()); }
            if pat.starts_with('*') && pat.ends_with('*') && pat.len() > 2 {
                let mid = &pat[1..pat.len() - 1];
                if n.contains(&mid.to_lowercase()) { return Some(pat.clone()); }
            } else if let Some(suffix) = pat.strip_prefix('*') {
                if n.ends_with(&suffix.to_lowercase()) { return Some(pat.clone()); }
            } else if let Some(prefix) = pat.strip_suffix('*') {
                if n.starts_with(&prefix.to_lowercase()) { return Some(pat.clone()); }
            } else if pat.to_lowercase() == n {
                return Some(pat.clone());
            }
        }
        None
    }

    /// Redact a name/value list. Returns vec of (name, value) where
    /// matched values are replaced with `[REDACTED:<len>]`.
    pub fn redact_args(&self, args: &[(String, String)]) -> Vec<(String, String)> {
        args.iter().map(|(n, v)| {
            if self.matches(n).is_some() {
                (n.clone(), format!("[REDACTED:{}]", v.chars().count()))
            } else {
                (n.clone(), v.clone())
            }
        }).collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RedactError> {
        if self.schema_version != SCHEMA_VERSION { return Err(RedactError::SchemaMismatch); }
        for p in &self.patterns {
            if p.is_empty() { return Err(RedactError::EmptyPattern); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arg(n: &str, v: &str) -> (String, String) { (n.into(), v.into()) }

    #[test]
    fn canonical_validates() {
        ToolArgRedactionPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn exact_match_redacts() {
        let p = ToolArgRedactionPolicy::canonical();
        let out = p.redact_args(&[arg("password", "hunter2")]);
        assert_eq!(out[0].1, "[REDACTED:7]");
    }

    #[test]
    fn case_insensitive_match() {
        let p = ToolArgRedactionPolicy::canonical();
        let out = p.redact_args(&[arg("Password", "secretvalue")]);
        assert_eq!(out[0].1, "[REDACTED:11]");
    }

    #[test]
    fn suffix_glob_token() {
        let p = ToolArgRedactionPolicy::canonical();
        let out = p.redact_args(&[arg("github_token", "ghp_xxx")]);
        assert_eq!(out[0].1, "[REDACTED:7]");
    }

    #[test]
    fn prefix_glob_aws() {
        let p = ToolArgRedactionPolicy::canonical();
        let out = p.redact_args(&[arg("aws_secret_access_key", "AKIA…")]);
        // matched by either "aws_*" or "*_key".
        assert!(out[0].1.starts_with("[REDACTED:"));
    }

    #[test]
    fn non_matching_left_alone() {
        let p = ToolArgRedactionPolicy::canonical();
        let out = p.redact_args(&[arg("city", "Montreal")]);
        assert_eq!(out[0].1, "Montreal");
    }

    #[test]
    fn wildcard_redacts_all() {
        let mut p = ToolArgRedactionPolicy::canonical();
        p.add("*").unwrap();
        let out = p.redact_args(&[arg("city", "Montreal")]);
        assert!(out[0].1.starts_with("[REDACTED:"));
    }

    #[test]
    fn empty_pattern_rejected() {
        let mut p = ToolArgRedactionPolicy::canonical();
        assert!(matches!(p.add("").unwrap_err(), RedactError::EmptyPattern));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = ToolArgRedactionPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), RedactError::SchemaMismatch));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = ToolArgRedactionPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: ToolArgRedactionPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
