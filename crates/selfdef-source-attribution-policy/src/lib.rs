//! `selfdef-source-attribution-policy` — citation requirement gate.
//!
//! Per ArtifactClass declares an AttributionRule (Required / Optional
//! / Forbidden). check(claims) returns Pass / MissingSources /
//! UnwantedSources.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Artifact class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactClass {
    /// Research summary / analysis.
    Research,
    /// Code commit message.
    CommitMessage,
    /// Source code (no sources expected in body).
    SourceCode,
    /// Operator-facing report.
    Report,
    /// Chat reply.
    ChatReply,
    /// Documentation page.
    Documentation,
}

/// Attribution rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttributionRule {
    /// Sources required (at least 1).
    Required,
    /// Sources optional (any count, including 0).
    Optional,
    /// Sources forbidden (must be 0).
    Forbidden,
}

/// One claim.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claim {
    /// Claim text.
    pub text: String,
    /// Source URIs / references.
    pub sources: Vec<String>,
}

/// Result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AttributionResult {
    /// Passes.
    Pass,
    /// Sources required but missing on some claims.
    MissingSources {
        /// indices of claims missing sources.
        claim_indices: Vec<usize>,
    },
    /// Sources forbidden but present.
    UnwantedSources {
        /// indices of claims with sources.
        claim_indices: Vec<usize>,
    },
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceAttributionPolicy {
    /// Schema version.
    pub schema_version: String,
    /// research rule.
    pub research: AttributionRule,
    /// commit-message rule.
    pub commit_message: AttributionRule,
    /// source-code rule.
    pub source_code: AttributionRule,
    /// report rule.
    pub report: AttributionRule,
    /// chat-reply rule.
    pub chat_reply: AttributionRule,
    /// documentation rule.
    pub documentation: AttributionRule,
}

/// Errors.
#[derive(Debug, Error)]
pub enum AttributionError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

impl SourceAttributionPolicy {
    /// Canonical:
    /// Research/Documentation/Report = Required, ChatReply/CommitMessage = Optional,
    /// SourceCode = Forbidden.
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            research: AttributionRule::Required,
            commit_message: AttributionRule::Optional,
            source_code: AttributionRule::Forbidden,
            report: AttributionRule::Required,
            chat_reply: AttributionRule::Optional,
            documentation: AttributionRule::Required,
        }
    }

    /// Rule for a class.
    pub fn rule(&self, class: ArtifactClass) -> AttributionRule {
        match class {
            ArtifactClass::Research => self.research,
            ArtifactClass::CommitMessage => self.commit_message,
            ArtifactClass::SourceCode => self.source_code,
            ArtifactClass::Report => self.report,
            ArtifactClass::ChatReply => self.chat_reply,
            ArtifactClass::Documentation => self.documentation,
        }
    }

    /// Check.
    pub fn check(&self, class: ArtifactClass, claims: &[Claim]) -> AttributionResult {
        match self.rule(class) {
            AttributionRule::Required => {
                let missing: Vec<usize> = claims.iter().enumerate()
                    .filter_map(|(i, c)| if c.sources.is_empty() { Some(i) } else { None })
                    .collect();
                if missing.is_empty() {
                    AttributionResult::Pass
                } else {
                    AttributionResult::MissingSources { claim_indices: missing }
                }
            }
            AttributionRule::Optional => AttributionResult::Pass,
            AttributionRule::Forbidden => {
                let unwanted: Vec<usize> = claims.iter().enumerate()
                    .filter_map(|(i, c)| if !c.sources.is_empty() { Some(i) } else { None })
                    .collect();
                if unwanted.is_empty() {
                    AttributionResult::Pass
                } else {
                    AttributionResult::UnwantedSources { claim_indices: unwanted }
                }
            }
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), AttributionError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(AttributionError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(text: &str, sources: &[&str]) -> Claim {
        Claim {
            text: text.into(),
            sources: sources.iter().map(|s| (*s).into()).collect(),
        }
    }

    #[test]
    fn canonical_validates() {
        SourceAttributionPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn research_with_sources_passes() {
        let p = SourceAttributionPolicy::canonical();
        let r = p.check(ArtifactClass::Research, &[c("claim", &["https://a"])]);
        assert!(matches!(r, AttributionResult::Pass));
    }

    #[test]
    fn research_missing_sources_reported() {
        let p = SourceAttributionPolicy::canonical();
        let r = p.check(ArtifactClass::Research, &[c("claim", &[]), c("other", &["https://b"])]);
        match r {
            AttributionResult::MissingSources { claim_indices } => {
                assert_eq!(claim_indices, vec![0]);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn source_code_with_sources_rejected() {
        let p = SourceAttributionPolicy::canonical();
        let r = p.check(ArtifactClass::SourceCode, &[c("body", &["https://a"])]);
        assert!(matches!(r, AttributionResult::UnwantedSources { .. }));
    }

    #[test]
    fn chat_reply_optional_no_sources_ok() {
        let p = SourceAttributionPolicy::canonical();
        let r = p.check(ArtifactClass::ChatReply, &[c("hi", &[])]);
        assert!(matches!(r, AttributionResult::Pass));
    }

    #[test]
    fn chat_reply_optional_with_sources_ok() {
        let p = SourceAttributionPolicy::canonical();
        let r = p.check(ArtifactClass::ChatReply, &[c("hi", &["https://a"])]);
        assert!(matches!(r, AttributionResult::Pass));
    }

    #[test]
    fn empty_claims_pass_everywhere() {
        let p = SourceAttributionPolicy::canonical();
        for c in [ArtifactClass::Research, ArtifactClass::SourceCode, ArtifactClass::ChatReply] {
            assert!(matches!(p.check(c, &[]), AttributionResult::Pass));
        }
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = SourceAttributionPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), AttributionError::SchemaMismatch));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(serde_json::to_string(&ArtifactClass::CommitMessage).unwrap(), "\"commit-message\"");
        assert_eq!(serde_json::to_string(&ArtifactClass::ChatReply).unwrap(), "\"chat-reply\"");
    }

    #[test]
    fn rule_serde_kebab() {
        assert_eq!(serde_json::to_string(&AttributionRule::Required).unwrap(), "\"required\"");
        assert_eq!(serde_json::to_string(&AttributionRule::Forbidden).unwrap(), "\"forbidden\"");
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = SourceAttributionPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: SourceAttributionPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
