//! `selfdef-profile-mirror` — MS007 typed-mirror crate exposing the
//! selfdef MS040 active authority-profile + transition history
//! READ-ONLY for the sovereign-os D-02 profile-choices dashboard.
//!
//! Per MS043 R10183 + R10212, mirrors expose state read-only; profile
//! switches are `selfdefctl` + MS003-signed operator verbs on the IPS
//! side ONLY — sovereign-os NEVER mutates IPS state.
//!
//! Composes with:
//! - MS040 six-profile authority matrix (private/fast/careful/
//!   autonomous/experimental/production), the `Profile` taxonomy of
//!   `selfdef-profile-authority-gate`
//! - MS039 L0..L6 authority levels + Ring 0..4 trust topology (the
//!   per-profile `envelope` summary)
//! - MS011 Z-3 / SDD-026 flex-profile (`baseline` is the active
//!   authority-profile name the publisher projects into `active`)
//!
//! This is the published wire schema only — dependency-light (serde +
//! thiserror), no IPS logic. The selfdef daemon owns the projection
//! from live state into a [`ProfileMirrorSnapshot`]; sovereign-os's
//! `scripts/mirror/selfdef-profile-mirror.py` consumes it.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version. Bump on breaking changes; consumers MUST refuse
/// unknown major versions.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// MS040 six-profile authority discriminator. Serializes to the
/// operator-readable lowercase token the D-02 dashboard renders
/// (`private`, `fast`, …) — wire-stable with the consumer's
/// `PROFILES` allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    /// Private — local observe/suggest only unless explicitly approved.
    Private,
    /// Fast — bounded L4 Execute for safe tools (Tier A).
    Fast,
    /// Careful — oracle + test gates before L5 Commit.
    Careful,
    /// Autonomous — execute bounded tasks within a predeclared envelope.
    Autonomous,
    /// Experimental — high exploration in Tier C/D sandbox, zero host commit.
    Experimental,
    /// Production — strict commit gates, strong trace, rollback required.
    Production,
}

impl Profile {
    /// Operator-readable token (matches the serde serialization).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Fast => "fast",
            Self::Careful => "careful",
            Self::Autonomous => "autonomous",
            Self::Experimental => "experimental",
            Self::Production => "production",
        }
    }

    /// Parse the operator-readable token. Returns `None` for unknown
    /// names so the publisher can fall back to the MS040 R09535
    /// default (Private) rather than fabricate a profile.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "private" => Some(Self::Private),
            "fast" => Some(Self::Fast),
            "careful" => Some(Self::Careful),
            "autonomous" => Some(Self::Autonomous),
            "experimental" => Some(Self::Experimental),
            "production" => Some(Self::Production),
            _ => None,
        }
    }
}

/// One authority-profile transition — operator-actionable provenance
/// of a switch between two MS040 profiles. The D-02 dashboard renders
/// these as the profile-history timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileTransition {
    /// ISO-8601 UTC timestamp of the switch.
    pub ts: String,
    /// Profile switched away from (operator-readable token).
    pub from: String,
    /// Profile switched to (operator-readable token).
    pub to: String,
    /// MS003 fingerprint of the operator who switched.
    pub actor: String,
    /// Operator-authored reason (non-empty per MS041 R09657).
    pub rationale: String,
    /// MS003 signature over the transition envelope (hex-encoded).
    pub signature: String,
}

/// Top-level mirror snapshot consumed by sovereign-os D-02 dashboard.
///
/// The active authority-profile selection has no top-level signature
/// (it is not a signed artifact — each *transition* carries its own
/// MS003 signature in [`ProfileTransition::signature`]).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileMirrorSnapshot {
    /// Wire-stable schema version. MUST equal [`SCHEMA_VERSION`].
    pub schema_version: String,
    /// The currently-active MS040 authority profile.
    pub active: Profile,
    /// ISO-8601 UTC timestamp the active profile has held since, or a
    /// `"—"`-style marker when the publisher cannot determine it.
    pub since: String,
    /// MS003 fingerprint of the operator who selected the active
    /// profile, or `"unknown"` when not tracked.
    pub actor: String,
    /// MS040 envelope summary for the active profile (e.g. the
    /// max authority level + max trust ring), rendered by the
    /// publisher from the authority-gate. Operator-readable.
    pub envelope: String,
    /// Profile-switch history, oldest-first. Empty when no switch
    /// history is tracked yet.
    pub history: Vec<ProfileTransition>,
}

/// Errors a consumer may surface when reading this mirror.
#[derive(Debug, Error)]
pub enum MirrorError {
    /// Schema major version mismatch.
    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected version.
        expected: String,
        /// Observed version.
        actual: String,
    },
    /// MS003 signature verification failed.
    #[error("MS003 signature verification failed: {0}")]
    SignatureFailed(String),
    /// Deserialization failure.
    #[error("snapshot deserialization failed: {0}")]
    Deserialize(String),
}

impl ProfileMirrorSnapshot {
    /// Build a snapshot for `active` with no switch history. The
    /// publisher fills `since`/`actor`/`envelope` from live state.
    #[must_use]
    pub fn new(active: Profile, since: String, actor: String, envelope: String) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            active,
            since,
            actor,
            envelope,
            history: Vec::new(),
        }
    }

    /// Validate schema version. Same-major bumps OK per M061 R10297.
    pub fn validate_schema(&self) -> Result<(), MirrorError> {
        if self.schema_version == SCHEMA_VERSION {
            return Ok(());
        }
        let snap_major = self.schema_version.split('.').next().unwrap_or("");
        let exp_major = SCHEMA_VERSION.split('.').next().unwrap_or("");
        if snap_major != exp_major {
            return Err(MirrorError::SchemaMismatch {
                expected: SCHEMA_VERSION.into(),
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(active: Profile) -> ProfileMirrorSnapshot {
        ProfileMirrorSnapshot::new(
            active,
            "2026-05-28T00:00:00Z".into(),
            "operator-fp".into(),
            "≤ L1Suggest · ≤ Ring2".into(),
        )
    }

    #[test]
    fn schema_validates_canonical() {
        snap(Profile::Private).validate_schema().unwrap();
    }

    #[test]
    fn schema_rejects_major_drift() {
        let mut s = snap(Profile::Fast);
        s.schema_version = "2.0.0".into();
        assert!(matches!(
            s.validate_schema().unwrap_err(),
            MirrorError::SchemaMismatch { .. }
        ));
    }

    #[test]
    fn schema_accepts_minor_bump() {
        let mut s = snap(Profile::Careful);
        s.schema_version = "1.7.0".into();
        s.validate_schema().unwrap();
    }

    #[test]
    fn profile_serializes_snake_case() {
        // The D-02 consumer's PROFILES allowlist is lowercase tokens.
        for (p, token) in [
            (Profile::Private, "\"private\""),
            (Profile::Fast, "\"fast\""),
            (Profile::Careful, "\"careful\""),
            (Profile::Autonomous, "\"autonomous\""),
            (Profile::Experimental, "\"experimental\""),
            (Profile::Production, "\"production\""),
        ] {
            assert_eq!(serde_json::to_string(&p).unwrap(), token);
            assert_eq!(Profile::from_token(p.as_str()), Some(p));
        }
    }

    #[test]
    fn from_token_rejects_unknown() {
        assert_eq!(Profile::from_token("godmode"), None);
    }

    #[test]
    fn new_starts_with_empty_history() {
        assert!(snap(Profile::Production).history.is_empty());
    }

    #[test]
    fn json_round_trip() {
        let mut s = snap(Profile::Autonomous);
        s.history.push(ProfileTransition {
            ts: "2026-05-27T12:00:00Z".into(),
            from: "private".into(),
            to: "autonomous".into(),
            actor: "operator-fp".into(),
            rationale: "batch run".into(),
            signature: "deadbeef".into(),
        });
        let json = serde_json::to_string(&s).unwrap();
        let back: ProfileMirrorSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    /// The active-profile snapshot has NO top-level signature — only
    /// per-transition signatures. Confirms the field shape the D-02
    /// consumer (`selfdef-profile-mirror.py`) reads.
    #[test]
    fn snapshot_has_no_top_level_signature() {
        let json = serde_json::to_value(snap(Profile::Private)).unwrap();
        assert!(json.get("signature").is_none());
        assert!(json.get("active").is_some());
        assert!(json.get("envelope").is_some());
        assert!(json.get("history").is_some());
    }
}
