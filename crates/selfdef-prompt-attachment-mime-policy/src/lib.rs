//! `selfdef-prompt-attachment-mime-policy` — per-Profile MIME allowlist.
//!
//! Each Profile carries a `BTreeSet<String>` of MIME glob rules:
//!   * exact: `image/png`
//!   * subtype wildcard: `image/*`
//!   * full wildcard: `*`
//!
//! `classify(profile, mime)` returns `Allowed{matched}` /
//! `Denied{allowed}` / `Unconfigured`.
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
pub struct PromptAttachmentMimePolicy {
    /// Schema version.
    pub schema_version: String,
    /// Per-profile allowlists.
    pub profiles: BTreeMap<Profile, BTreeSet<String>>,
}

/// Verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum MimeVerdict {
    /// Allowed.
    Allowed {
        /// matched rule.
        matched: String,
    },
    /// Denied.
    Denied {
        /// allowed glob set snapshot.
        allowed: Vec<String>,
    },
    /// Profile unconfigured.
    Unconfigured,
}

/// Errors.
#[derive(Debug, Error)]
pub enum MimeError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty mime.
    #[error("mime tag empty")]
    EmptyMime,
    /// Malformed (no '/').
    #[error("malformed mime: {0}")]
    Malformed(String),
}

impl PromptAttachmentMimePolicy {
    /// Canonical.
    pub fn canonical() -> Self {
        let mut p = BTreeMap::new();
        p.insert(
            Profile::Private,
            ["image/png".into(), "image/jpeg".into()]
                .into_iter()
                .collect(),
        );
        p.insert(
            Profile::Fast,
            ["image/*".into(), "application/pdf".into()]
                .into_iter()
                .collect(),
        );
        p.insert(
            Profile::Careful,
            [
                "image/png".into(),
                "image/jpeg".into(),
                "application/pdf".into(),
            ]
            .into_iter()
            .collect(),
        );
        p.insert(
            Profile::Autonomous,
            [
                "image/*".into(),
                "application/pdf".into(),
                "text/plain".into(),
                "text/markdown".into(),
            ]
            .into_iter()
            .collect(),
        );
        p.insert(Profile::Experimental, ["*".into()].into_iter().collect());
        p.insert(
            Profile::Production,
            [
                "image/png".into(),
                "image/jpeg".into(),
                "application/pdf".into(),
            ]
            .into_iter()
            .collect(),
        );
        Self {
            schema_version: SCHEMA_VERSION.into(),
            profiles: p,
        }
    }

    /// Classify.
    pub fn classify(&self, profile: Profile, mime: &str) -> Result<MimeVerdict, MimeError> {
        if mime.is_empty() {
            return Err(MimeError::EmptyMime);
        }
        let slash = mime
            .find('/')
            .ok_or_else(|| MimeError::Malformed(mime.into()))?;
        let typ = &mime[..slash];
        let allow = match self.profiles.get(&profile) {
            Some(s) => s,
            None => return Ok(MimeVerdict::Unconfigured),
        };
        if allow.contains("*") {
            return Ok(MimeVerdict::Allowed {
                matched: "*".into(),
            });
        }
        if allow.contains(mime) {
            return Ok(MimeVerdict::Allowed {
                matched: mime.into(),
            });
        }
        let subtype_glob = format!("{}/*", typ);
        if allow.contains(&subtype_glob) {
            return Ok(MimeVerdict::Allowed {
                matched: subtype_glob,
            });
        }
        Ok(MimeVerdict::Denied {
            allowed: allow.iter().cloned().collect(),
        })
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), MimeError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(MimeError::SchemaMismatch);
        }
        for set in self.profiles.values() {
            for r in set {
                if r.is_empty() {
                    return Err(MimeError::EmptyMime);
                }
                if r != "*" && !r.contains('/') {
                    return Err(MimeError::Malformed(r.clone()));
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
        PromptAttachmentMimePolicy::canonical().validate().unwrap();
    }

    #[test]
    fn exact_match() {
        let c = PromptAttachmentMimePolicy::canonical();
        assert!(matches!(
            c.classify(Profile::Production, "image/png").unwrap(),
            MimeVerdict::Allowed { .. }
        ));
    }

    #[test]
    fn subtype_wildcard() {
        let c = PromptAttachmentMimePolicy::canonical();
        let v = c.classify(Profile::Fast, "image/webp").unwrap();
        match v {
            MimeVerdict::Allowed { matched } => assert_eq!(matched, "image/*"),
            _ => panic!("expected allowed"),
        }
    }

    #[test]
    fn denied_when_not_allowed() {
        let c = PromptAttachmentMimePolicy::canonical();
        assert!(matches!(
            c.classify(Profile::Production, "audio/mpeg").unwrap(),
            MimeVerdict::Denied { .. }
        ));
    }

    #[test]
    fn full_wildcard() {
        let c = PromptAttachmentMimePolicy::canonical();
        let v = c
            .classify(Profile::Experimental, "anything/anywhere")
            .unwrap();
        match v {
            MimeVerdict::Allowed { matched } => assert_eq!(matched, "*"),
            _ => panic!("expected allowed"),
        }
    }

    #[test]
    fn empty_mime_rejected() {
        let c = PromptAttachmentMimePolicy::canonical();
        assert!(matches!(
            c.classify(Profile::Production, "").unwrap_err(),
            MimeError::EmptyMime
        ));
    }

    #[test]
    fn malformed_mime_rejected() {
        let c = PromptAttachmentMimePolicy::canonical();
        assert!(matches!(
            c.classify(Profile::Production, "notmime").unwrap_err(),
            MimeError::Malformed(_)
        ));
    }

    #[test]
    fn unconfigured_profile() {
        let mut c = PromptAttachmentMimePolicy::canonical();
        c.profiles.clear();
        assert!(matches!(
            c.classify(Profile::Production, "image/png").unwrap(),
            MimeVerdict::Unconfigured
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = PromptAttachmentMimePolicy::canonical();
        c.schema_version = "9.9.9".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            MimeError::SchemaMismatch
        ));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let c = PromptAttachmentMimePolicy::canonical();
        let j = serde_json::to_string(&c).unwrap();
        let back: PromptAttachmentMimePolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
