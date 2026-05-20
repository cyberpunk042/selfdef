//! `selfdef-mcp-tool-arg-constraint` — per-arg value constraints.
//!
//! Each tool_id has a Vec<(arg_name, Constraint)> declared.
//! `check(tool_id, args)` evaluates each constraint against the
//! supplied `args: Vec<(name, value_string)>` and returns
//! `Ok` or `Violations { items }` listing each failing (arg, kind).
//!
//! Constraints:
//!   * `RequiredPresent` — arg must appear.
//!   * `ForbidEmpty` — arg value must not be empty.
//!   * `StrLenAtMost { max }` — value length ≤ max chars.
//!   * `StrEnum { allowed }` — value must be one of `allowed`.
//!   * `IntRange { min, max }` — value parses as i64 within range.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One constraint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Constraint {
    /// Arg must be present.
    RequiredPresent,
    /// Value must be non-empty.
    ForbidEmpty,
    /// Value length in chars ≤ max.
    StrLenAtMost {
        /// max chars.
        max: u32,
    },
    /// Value must be in the allowed set.
    StrEnum {
        /// allowed set.
        allowed: BTreeSet<String>,
    },
    /// Value parses i64 in [min, max].
    IntRange {
        /// min inclusive.
        min: i64,
        /// max inclusive.
        max: i64,
    },
}

/// One declaration: which arg, which constraint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Declaration {
    /// arg name.
    pub arg: String,
    /// constraint.
    pub constraint: Constraint,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpToolArgConstraint {
    /// Schema version.
    pub schema_version: String,
    /// tool_id → declarations.
    pub map: BTreeMap<String, Vec<Declaration>>,
}

/// One violation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Violation {
    /// arg name.
    pub arg: String,
    /// constraint that failed.
    pub constraint: Constraint,
    /// observed value (None means missing).
    pub observed: Option<String>,
}

/// Result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CheckOutcome {
    /// Passed.
    Ok,
    /// One or more violations.
    Violations {
        /// each failure.
        items: Vec<Violation>,
    },
    /// Tool not registered.
    UnknownTool,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ConstraintError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty tool id.
    #[error("tool id empty")]
    EmptyId,
    /// Empty arg.
    #[error("arg name empty")]
    EmptyArg,
}

impl McpToolArgConstraint {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            map: BTreeMap::new(),
        }
    }

    /// Register declarations.
    pub fn set(&mut self, tool_id: &str, declarations: Vec<Declaration>) -> Result<(), ConstraintError> {
        if tool_id.is_empty() { return Err(ConstraintError::EmptyId); }
        for d in &declarations {
            if d.arg.is_empty() { return Err(ConstraintError::EmptyArg); }
        }
        self.map.insert(tool_id.into(), declarations);
        Ok(())
    }

    /// Check.
    pub fn check(&self, tool_id: &str, args: &[(String, String)]) -> CheckOutcome {
        let decls = match self.map.get(tool_id) {
            Some(d) => d,
            None => return CheckOutcome::UnknownTool,
        };
        let lookup: BTreeMap<&str, &str> = args.iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let mut items = Vec::new();
        for d in decls {
            let observed = lookup.get(d.arg.as_str()).map(|s| s.to_string());
            if !Self::passes(&d.constraint, observed.as_deref()) {
                items.push(Violation {
                    arg: d.arg.clone(),
                    constraint: d.constraint.clone(),
                    observed,
                });
            }
        }
        if items.is_empty() { CheckOutcome::Ok } else { CheckOutcome::Violations { items } }
    }

    fn passes(c: &Constraint, observed: Option<&str>) -> bool {
        match c {
            Constraint::RequiredPresent => observed.is_some(),
            Constraint::ForbidEmpty => observed.is_some_and(|s| !s.is_empty()),
            Constraint::StrLenAtMost { max } => {
                observed.is_none_or(|s| (s.chars().count() as u32) <= *max)
            }
            Constraint::StrEnum { allowed } => {
                observed.is_none_or(|s| allowed.contains(s))
            }
            Constraint::IntRange { min, max } => {
                observed.is_none_or(|s| {
                    matches!(s.parse::<i64>(), Ok(n) if n >= *min && n <= *max)
                })
            }
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ConstraintError> {
        if self.schema_version != SCHEMA_VERSION { return Err(ConstraintError::SchemaMismatch); }
        for (id, decls) in &self.map {
            if id.is_empty() { return Err(ConstraintError::EmptyId); }
            for d in decls {
                if d.arg.is_empty() { return Err(ConstraintError::EmptyArg); }
            }
        }
        Ok(())
    }
}

impl Default for McpToolArgConstraint {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arg(n: &str, v: &str) -> (String, String) { (n.into(), v.into()) }

    #[test]
    fn required_present_pass() {
        let mut c = McpToolArgConstraint::new();
        c.set("t", vec![Declaration { arg: "x".into(), constraint: Constraint::RequiredPresent }]).unwrap();
        assert_eq!(c.check("t", &[arg("x", "v")]), CheckOutcome::Ok);
    }

    #[test]
    fn required_present_missing_violates() {
        let mut c = McpToolArgConstraint::new();
        c.set("t", vec![Declaration { arg: "x".into(), constraint: Constraint::RequiredPresent }]).unwrap();
        match c.check("t", &[]) {
            CheckOutcome::Violations { items } => {
                assert_eq!(items.len(), 1);
                assert_eq!(items[0].arg, "x");
                assert!(items[0].observed.is_none());
            }
            _ => panic!("expected violations"),
        }
    }

    #[test]
    fn forbid_empty_pass() {
        let mut c = McpToolArgConstraint::new();
        c.set("t", vec![Declaration { arg: "x".into(), constraint: Constraint::ForbidEmpty }]).unwrap();
        assert_eq!(c.check("t", &[arg("x", "v")]), CheckOutcome::Ok);
        assert!(matches!(c.check("t", &[arg("x", "")]), CheckOutcome::Violations { .. }));
    }

    #[test]
    fn str_len_at_most() {
        let mut c = McpToolArgConstraint::new();
        c.set("t", vec![Declaration { arg: "x".into(), constraint: Constraint::StrLenAtMost { max: 3 } }]).unwrap();
        assert_eq!(c.check("t", &[arg("x", "ab")]), CheckOutcome::Ok);
        assert!(matches!(c.check("t", &[arg("x", "abcd")]), CheckOutcome::Violations { .. }));
    }

    #[test]
    fn str_enum() {
        let mut c = McpToolArgConstraint::new();
        let mut allowed = BTreeSet::new();
        allowed.insert("on".into());
        allowed.insert("off".into());
        c.set("t", vec![Declaration { arg: "mode".into(), constraint: Constraint::StrEnum { allowed } }]).unwrap();
        assert_eq!(c.check("t", &[arg("mode", "on")]), CheckOutcome::Ok);
        assert!(matches!(c.check("t", &[arg("mode", "wat")]), CheckOutcome::Violations { .. }));
    }

    #[test]
    fn int_range() {
        let mut c = McpToolArgConstraint::new();
        c.set("t", vec![Declaration { arg: "n".into(), constraint: Constraint::IntRange { min: 1, max: 10 } }]).unwrap();
        assert_eq!(c.check("t", &[arg("n", "5")]), CheckOutcome::Ok);
        assert!(matches!(c.check("t", &[arg("n", "20")]), CheckOutcome::Violations { .. }));
        assert!(matches!(c.check("t", &[arg("n", "nope")]), CheckOutcome::Violations { .. }));
    }

    #[test]
    fn multiple_violations_reported() {
        let mut c = McpToolArgConstraint::new();
        c.set("t", vec![
            Declaration { arg: "x".into(), constraint: Constraint::RequiredPresent },
            Declaration { arg: "y".into(), constraint: Constraint::StrLenAtMost { max: 3 } },
        ]).unwrap();
        match c.check("t", &[arg("y", "abcd")]) {
            CheckOutcome::Violations { items } => assert_eq!(items.len(), 2),
            _ => panic!(),
        }
    }

    #[test]
    fn unknown_tool() {
        let c = McpToolArgConstraint::new();
        assert_eq!(c.check("nope", &[]), CheckOutcome::UnknownTool);
    }

    #[test]
    fn empty_arg_rejected() {
        let mut c = McpToolArgConstraint::new();
        assert!(matches!(
            c.set("t", vec![Declaration { arg: "".into(), constraint: Constraint::RequiredPresent }]).unwrap_err(),
            ConstraintError::EmptyArg
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = McpToolArgConstraint::new();
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), ConstraintError::SchemaMismatch));
    }

    #[test]
    fn constraint_serde_roundtrip() {
        let mut c = McpToolArgConstraint::new();
        c.set("t", vec![Declaration { arg: "x".into(), constraint: Constraint::ForbidEmpty }]).unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: McpToolArgConstraint = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
