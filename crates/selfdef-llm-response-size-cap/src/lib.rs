//! `selfdef-llm-response-size-cap` — per-Profile cap on a single response's shape.
//!
//! Each Profile carries:
//!   * `max_completion_tokens`
//!   * `max_response_chars`
//!   * `max_attached_blobs`
//!
//! `plan(req)` returns:
//!   * `Granted` — request fits.
//!   * `Capped{adjusted}` — at least one field over cap; the
//!     adjusted request is clamped to the per-Profile caps.
//!   * `RejectedShape{reason}` — invariant violated (e.g.
//!     requested_chars 0, attached negative — impossible with u32).
//!   * `Unconfigured` — no config for this profile.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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

/// Per-Profile cap.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileResponseCap {
    /// Max completion tokens.
    pub max_completion_tokens: u32,
    /// Max response chars (UTF-8 chars, not bytes).
    pub max_response_chars: u32,
    /// Max attached blobs (images, files).
    pub max_attached_blobs: u32,
}

/// One requested shape.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResponseRequest {
    /// requested.
    pub completion_tokens: u32,
    /// requested.
    pub response_chars: u32,
    /// requested.
    pub attached_blobs: u32,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResponseSizeCap {
    /// Schema version.
    pub schema_version: String,
    /// Per-profile caps.
    pub profiles: BTreeMap<Profile, ProfileResponseCap>,
}

/// Plan verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PlanVerdict {
    /// Within caps.
    Granted,
    /// Clamped to caps.
    Capped {
        /// adjusted shape.
        adjusted: ResponseRequest,
    },
    /// Profile unconfigured.
    Unconfigured,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CapError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

impl ResponseSizeCap {
    /// Canonical defaults.
    pub fn canonical() -> Self {
        let mut p = BTreeMap::new();
        p.insert(Profile::Private,      ProfileResponseCap { max_completion_tokens: 2048,  max_response_chars: 8000,    max_attached_blobs: 2 });
        p.insert(Profile::Fast,         ProfileResponseCap { max_completion_tokens: 4096,  max_response_chars: 16_000,  max_attached_blobs: 4 });
        p.insert(Profile::Careful,      ProfileResponseCap { max_completion_tokens: 2048,  max_response_chars: 8000,    max_attached_blobs: 2 });
        p.insert(Profile::Autonomous,   ProfileResponseCap { max_completion_tokens: 8192,  max_response_chars: 32_000,  max_attached_blobs: 8 });
        p.insert(Profile::Experimental, ProfileResponseCap { max_completion_tokens: 16_384,max_response_chars: 64_000,  max_attached_blobs: 16 });
        p.insert(Profile::Production,   ProfileResponseCap { max_completion_tokens: 4096,  max_response_chars: 16_000,  max_attached_blobs: 4 });
        Self {
            schema_version: SCHEMA_VERSION.into(),
            profiles: p,
        }
    }

    /// Plan.
    pub fn plan(&self, profile: Profile, req: ResponseRequest) -> PlanVerdict {
        let cfg = match self.profiles.get(&profile) {
            Some(c) => *c,
            None => return PlanVerdict::Unconfigured,
        };
        let over = req.completion_tokens > cfg.max_completion_tokens
            || req.response_chars > cfg.max_response_chars
            || req.attached_blobs > cfg.max_attached_blobs;
        if !over { return PlanVerdict::Granted; }
        PlanVerdict::Capped {
            adjusted: ResponseRequest {
                completion_tokens: req.completion_tokens.min(cfg.max_completion_tokens),
                response_chars: req.response_chars.min(cfg.max_response_chars),
                attached_blobs: req.attached_blobs.min(cfg.max_attached_blobs),
            },
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CapError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CapError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(t: u32, c: u32, b: u32) -> ResponseRequest {
        ResponseRequest { completion_tokens: t, response_chars: c, attached_blobs: b }
    }

    #[test]
    fn canonical_validates() {
        ResponseSizeCap::canonical().validate().unwrap();
    }

    #[test]
    fn grant_under_caps() {
        let c = ResponseSizeCap::canonical();
        assert_eq!(c.plan(Profile::Fast, req(100, 1000, 1)), PlanVerdict::Granted);
    }

    #[test]
    fn cap_tokens_only() {
        let c = ResponseSizeCap::canonical();
        let v = c.plan(Profile::Production, req(10_000, 500, 1));
        match v {
            PlanVerdict::Capped { adjusted } => {
                assert_eq!(adjusted.completion_tokens, 4096);
                assert_eq!(adjusted.response_chars, 500);
                assert_eq!(adjusted.attached_blobs, 1);
            }
            _ => panic!("expected capped"),
        }
    }

    #[test]
    fn cap_all_fields() {
        let c = ResponseSizeCap::canonical();
        let v = c.plan(Profile::Private, req(99_999, 99_999, 99));
        match v {
            PlanVerdict::Capped { adjusted } => {
                assert_eq!(adjusted.completion_tokens, 2048);
                assert_eq!(adjusted.response_chars, 8000);
                assert_eq!(adjusted.attached_blobs, 2);
            }
            _ => panic!("expected capped"),
        }
    }

    #[test]
    fn unconfigured_profile() {
        let mut c = ResponseSizeCap::canonical();
        c.profiles.clear();
        assert_eq!(c.plan(Profile::Fast, req(10, 10, 0)), PlanVerdict::Unconfigured);
    }

    #[test]
    fn per_profile_isolation() {
        let c = ResponseSizeCap::canonical();
        // Experimental allows much bigger responses.
        assert_eq!(c.plan(Profile::Experimental, req(10_000, 50_000, 10)), PlanVerdict::Granted);
        // Same request capped under Production.
        assert!(matches!(c.plan(Profile::Production, req(10_000, 50_000, 10)), PlanVerdict::Capped { .. }));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = ResponseSizeCap::canonical();
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), CapError::SchemaMismatch));
    }

    #[test]
    fn cap_serde_roundtrip() {
        let c = ResponseSizeCap::canonical();
        let j = serde_json::to_string(&c).unwrap();
        let back: ResponseSizeCap = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
