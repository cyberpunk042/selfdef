//! `selfdef-policy-explanation-formatter` — operator-readable text.
//!
//! Builds Explanation { headline, detail_lines, fix_suggestions }
//! from (policy_id, reason_code, ContextMap). Pure UX/text projection.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Explanation block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Explanation {
    /// Schema version.
    pub schema_version: String,
    /// Short headline (≤ 80 chars).
    pub headline: String,
    /// Detail lines (each ≤ 120 chars).
    pub detail_lines: Vec<String>,
    /// Suggested fixes (each ≤ 120 chars).
    pub fix_suggestions: Vec<String>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ExplainError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty policy_id.
    #[error("policy_id empty")]
    EmptyPolicyId,
    /// Empty reason_code.
    #[error("reason_code empty")]
    EmptyReasonCode,
    /// Headline too long.
    #[error("headline length {0} > 80")]
    HeadlineTooLong(usize),
    /// Detail line too long.
    #[error("detail line index {0} length {1} > 120")]
    DetailLineTooLong(usize, usize),
    /// Suggestion too long.
    #[error("fix suggestion index {0} length {1} > 120")]
    SuggestionTooLong(usize, usize),
}

/// Formatter (stateless).
#[derive(Debug, Clone, Default)]
pub struct PolicyExplanationFormatter;

impl PolicyExplanationFormatter {
    /// Format.
    pub fn format(
        policy_id: &str,
        reason_code: &str,
        context: &BTreeMap<String, String>,
    ) -> Result<Explanation, ExplainError> {
        if policy_id.is_empty() {
            return Err(ExplainError::EmptyPolicyId);
        }
        if reason_code.is_empty() {
            return Err(ExplainError::EmptyReasonCode);
        }
        let headline = format!("Policy '{policy_id}' denied: {reason_code}");
        if headline.chars().count() > 80 {
            return Err(ExplainError::HeadlineTooLong(headline.chars().count()));
        }
        let mut detail_lines: Vec<String> = Vec::with_capacity(context.len() + 1);
        detail_lines.push(format!("Reason code: {reason_code}"));
        for (k, v) in context {
            let line = format!("  {k}: {v}");
            if line.chars().count() > 120 {
                return Err(ExplainError::DetailLineTooLong(
                    detail_lines.len(),
                    line.chars().count(),
                ));
            }
            detail_lines.push(line);
        }
        let fix_suggestions = match reason_code {
            "quota-exhausted" => vec![
                "Wait for the quota window to reset, or raise the cap in operator settings.".into(),
            ],
            "approval-required" => {
                vec!["Trigger an operator-approval flow before re-attempting the action.".into()]
            }
            "schema-drift" => {
                vec!["Refresh the engine and re-apply the affected rule bundle.".into()]
            }
            "emergency-stop-engaged" => {
                vec!["Release the kill switch with the configured release authority.".into()]
            }
            _ => vec![],
        };
        Ok(Explanation {
            schema_version: SCHEMA_VERSION.into(),
            headline,
            detail_lines,
            fix_suggestions,
        })
    }
}

impl Explanation {
    /// Validate.
    pub fn validate(&self) -> Result<(), ExplainError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ExplainError::SchemaMismatch);
        }
        if self.headline.chars().count() > 80 {
            return Err(ExplainError::HeadlineTooLong(self.headline.chars().count()));
        }
        for (i, line) in self.detail_lines.iter().enumerate() {
            if line.chars().count() > 120 {
                return Err(ExplainError::DetailLineTooLong(i, line.chars().count()));
            }
        }
        for (i, sug) in self.fix_suggestions.iter().enumerate() {
            if sug.chars().count() > 120 {
                return Err(ExplainError::SuggestionTooLong(i, sug.chars().count()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_policy_rejected() {
        assert!(matches!(
            PolicyExplanationFormatter::format("", "quota-exhausted", &BTreeMap::new())
                .unwrap_err(),
            ExplainError::EmptyPolicyId
        ));
    }

    #[test]
    fn empty_reason_rejected() {
        assert!(matches!(
            PolicyExplanationFormatter::format("p", "", &BTreeMap::new()).unwrap_err(),
            ExplainError::EmptyReasonCode
        ));
    }

    #[test]
    fn quota_suggestion_emitted() {
        let r =
            PolicyExplanationFormatter::format("rate-limit", "quota-exhausted", &BTreeMap::new())
                .unwrap();
        assert_eq!(r.fix_suggestions.len(), 1);
    }

    #[test]
    fn approval_suggestion_emitted() {
        let r =
            PolicyExplanationFormatter::format("p", "approval-required", &BTreeMap::new()).unwrap();
        assert_eq!(r.fix_suggestions.len(), 1);
    }

    #[test]
    fn unknown_reason_no_suggestion() {
        let r = PolicyExplanationFormatter::format("p", "policy-other", &BTreeMap::new()).unwrap();
        assert!(r.fix_suggestions.is_empty());
    }

    #[test]
    fn context_in_detail_lines() {
        let mut ctx = BTreeMap::new();
        ctx.insert("subject".into(), "ops-1".into());
        let r = PolicyExplanationFormatter::format("p", "quota-exhausted", &ctx).unwrap();
        assert!(r.detail_lines.iter().any(|l| l.contains("subject")));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r =
            PolicyExplanationFormatter::format("p", "policy-other", &BTreeMap::new()).unwrap();
        r.schema_version = "9.9.9".into();
        assert!(matches!(
            r.validate().unwrap_err(),
            ExplainError::SchemaMismatch
        ));
    }

    #[test]
    fn detail_too_long_rejected_on_validate() {
        let mut r =
            PolicyExplanationFormatter::format("p", "policy-other", &BTreeMap::new()).unwrap();
        r.detail_lines.push("x".repeat(130));
        assert!(matches!(
            r.validate().unwrap_err(),
            ExplainError::DetailLineTooLong(_, _)
        ));
    }

    #[test]
    fn headline_within_80() {
        let r = PolicyExplanationFormatter::format("p", "policy-other", &BTreeMap::new()).unwrap();
        assert!(r.headline.chars().count() <= 80);
    }

    #[test]
    fn explanation_serde_roundtrip() {
        let r =
            PolicyExplanationFormatter::format("p", "quota-exhausted", &BTreeMap::new()).unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: Explanation = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
