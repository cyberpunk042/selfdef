//! `selfdef-prompt-language-allowlist` — per-Profile allowed-input-language gate.
//!
//! Each Profile has a `BTreeSet<String>` of BCP-47 tags (lowercased
//! primary subtag for matching: `en`, `fr`, `zh-hans`). Match logic:
//!
//!   * Exact tag (lowercased).
//!   * Primary-subtag fallback: `en-US` matches `en`.
//!
//! Wildcard `"*"` in an allowlist permits any tag.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// Private.
    Private,
    /// Fast.
    Fast,
    /// Careful.
    Careful,
    /// Autonomous.
    Autonomous,
    /// Experimental.
    Experimental,
    /// Production.
    Production,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromptLanguageAllowlist {
    /// Schema version.
    pub schema_version: String,
    /// Per-profile allow set.
    pub profiles: BTreeMap<Profile, BTreeSet<String>>,
}

/// Verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum LangVerdict {
    /// Allowed.
    Allowed {
        /// matched rule (e.g. "en", "*", "zh-hans").
        matched: String,
    },
    /// Denied.
    Denied {
        /// allowed set snapshot.
        allowed: Vec<String>,
    },
    /// Profile unconfigured.
    Unconfigured,
}

/// Errors.
#[derive(Debug, Error)]
pub enum LangError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty tag.
    #[error("language tag empty")]
    EmptyTag,
}

impl PromptLanguageAllowlist {
    /// Canonical defaults: Production = en/fr, Experimental = wildcard.
    pub fn canonical() -> Self {
        let mut p = BTreeMap::new();
        p.insert(
            Profile::Private,
            ["en".into(), "fr".into()].into_iter().collect(),
        );
        p.insert(
            Profile::Fast,
            ["en".into(), "fr".into(), "es".into(), "de".into()]
                .into_iter()
                .collect(),
        );
        p.insert(
            Profile::Careful,
            ["en".into(), "fr".into()].into_iter().collect(),
        );
        p.insert(
            Profile::Autonomous,
            [
                "en".into(),
                "fr".into(),
                "es".into(),
                "de".into(),
                "ja".into(),
                "zh-hans".into(),
            ]
            .into_iter()
            .collect(),
        );
        p.insert(Profile::Experimental, ["*".into()].into_iter().collect());
        p.insert(
            Profile::Production,
            ["en".into(), "fr".into()].into_iter().collect(),
        );
        Self {
            schema_version: SCHEMA_VERSION.into(),
            profiles: p,
        }
    }

    /// Classify a detected tag.
    pub fn classify(&self, profile: Profile, detected: &str) -> Result<LangVerdict, LangError> {
        if detected.is_empty() {
            return Err(LangError::EmptyTag);
        }
        let allow = match self.profiles.get(&profile) {
            Some(s) => s,
            None => return Ok(LangVerdict::Unconfigured),
        };
        let lower = detected.to_lowercase();
        if allow.contains("*") {
            return Ok(LangVerdict::Allowed {
                matched: "*".into(),
            });
        }
        if allow.contains(&lower) {
            return Ok(LangVerdict::Allowed { matched: lower });
        }
        if let Some(prim) = lower.split('-').next() {
            if allow.contains(prim) {
                return Ok(LangVerdict::Allowed {
                    matched: prim.into(),
                });
            }
        }
        Ok(LangVerdict::Denied {
            allowed: allow.iter().cloned().collect(),
        })
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), LangError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(LangError::SchemaMismatch);
        }
        for set in self.profiles.values() {
            for t in set {
                if t.is_empty() {
                    return Err(LangError::EmptyTag);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        PromptLanguageAllowlist::canonical().validate().unwrap();
    }

    #[test]
    fn exact_match() {
        let c = PromptLanguageAllowlist::canonical();
        assert!(matches!(
            c.classify(Profile::Production, "en").unwrap(),
            LangVerdict::Allowed { .. }
        ));
    }

    #[test]
    fn primary_subtag_fallback() {
        let c = PromptLanguageAllowlist::canonical();
        let v = c.classify(Profile::Production, "en-US").unwrap();
        match v {
            LangVerdict::Allowed { matched } => assert_eq!(matched, "en"),
            _ => panic!("expected allowed"),
        }
    }

    #[test]
    fn denied_when_not_in_set() {
        let c = PromptLanguageAllowlist::canonical();
        assert!(matches!(
            c.classify(Profile::Production, "ja").unwrap(),
            LangVerdict::Denied { .. }
        ));
    }

    #[test]
    fn wildcard_allows_anything() {
        let c = PromptLanguageAllowlist::canonical();
        let v = c.classify(Profile::Experimental, "ko").unwrap();
        match v {
            LangVerdict::Allowed { matched } => assert_eq!(matched, "*"),
            _ => panic!("expected allowed"),
        }
    }

    #[test]
    fn empty_tag_rejected() {
        let c = PromptLanguageAllowlist::canonical();
        assert!(matches!(
            c.classify(Profile::Production, "").unwrap_err(),
            LangError::EmptyTag
        ));
    }

    #[test]
    fn unconfigured_profile() {
        let mut c = PromptLanguageAllowlist::canonical();
        c.profiles.clear();
        assert!(matches!(
            c.classify(Profile::Production, "en").unwrap(),
            LangVerdict::Unconfigured
        ));
    }

    #[test]
    fn case_insensitive() {
        let c = PromptLanguageAllowlist::canonical();
        assert!(matches!(
            c.classify(Profile::Production, "EN-us").unwrap(),
            LangVerdict::Allowed { .. }
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = PromptLanguageAllowlist::canonical();
        c.schema_version = "9.9.9".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            LangError::SchemaMismatch
        ));
    }

    #[test]
    fn allowlist_serde_roundtrip() {
        let c = PromptLanguageAllowlist::canonical();
        let j = serde_json::to_string(&c).unwrap();
        let back: PromptLanguageAllowlist = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
