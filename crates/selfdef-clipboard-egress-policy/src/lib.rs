//! `selfdef-clipboard-egress-policy` — clipboard egress authority.
//!
//! Clipboard is a high-bandwidth exfiltration channel. This crate
//! encodes which `ContextSensitivity` classes may flow to which
//! clipboard target (local-only / cross-profile / external-paste-
//! buffer) under which profile, and which require per-event operator
//! approval.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Sensitivity class of clipboard payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContextSensitivity {
    /// Public (websearch, docs).
    Public,
    /// Internal (operator's drafts, internal notes).
    Internal,
    /// Confidential (PII, credentials, private code).
    Confidential,
    /// Top-Secret (signing keys, secret tokens, master credentials).
    TopSecret,
}

/// Clipboard target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClipboardTarget {
    /// Internal in-engine clipboard (cockpit pane → cockpit pane).
    LocalOnly,
    /// Cross-profile clipboard (one profile → another).
    CrossProfile,
    /// External OS paste buffer (system-wide, can be read by any app).
    ExternalPasteBuffer,
}

/// Operator profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

/// Per-event decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClipboardDecision {
    /// Allowed without further checks.
    Allow,
    /// Allowed but per-event operator approval required.
    Ask,
    /// Denied outright.
    Deny,
}

/// Operator approval state for the current copy event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalState {
    /// Not asked yet.
    Unasked,
    /// Operator approved this event.
    Approved,
    /// Operator declined this event.
    Declined,
}

/// Clipboard egress policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClipboardEgressPolicy {
    /// Schema version.
    pub schema_version: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ClipboardEgressError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Top-secret never escapes the engine.
    #[error("top-secret payload may never reach clipboard")]
    TopSecretForbidden,
    /// Confidential reached external paste buffer.
    #[error("confidential payload may not reach external paste buffer")]
    ConfidentialExternalForbidden,
    /// Operator declined.
    #[error("operator declined clipboard egress")]
    OperatorDeclined,
    /// Ask decision but approval state unasked.
    #[error("decision Ask requires operator approval first")]
    ApprovalRequired,
}

impl ClipboardEgressPolicy {
    /// New canonical policy.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
        }
    }

    /// Static decision table (sensitivity × target × profile → decision).
    ///
    /// Rules:
    /// * TopSecret → always Deny.
    /// * Confidential → ExternalPasteBuffer always Deny;
    ///   CrossProfile → Ask; LocalOnly → Ask under Production /
    ///   Autonomous, otherwise Allow.
    /// * Internal → CrossProfile + ExternalPasteBuffer → Ask under
    ///   Production; otherwise Allow.
    /// * Public → Allow everywhere.
    pub fn decide(
        &self,
        sensitivity: ContextSensitivity,
        target: ClipboardTarget,
        profile: Profile,
    ) -> ClipboardDecision {
        use ClipboardDecision::*;
        use ClipboardTarget::*;
        use ContextSensitivity::*;
        match sensitivity {
            TopSecret => Deny,
            Confidential => match target {
                ExternalPasteBuffer => Deny,
                CrossProfile => Ask,
                LocalOnly => match profile {
                    Profile::Production | Profile::Autonomous => Ask,
                    _ => Allow,
                },
            },
            Internal => match target {
                ExternalPasteBuffer | CrossProfile => match profile {
                    Profile::Production => Ask,
                    _ => Allow,
                },
                LocalOnly => Allow,
            },
            Public => Allow,
        }
    }

    /// Gate a copy event end-to-end with approval state.
    pub fn gate(
        &self,
        sensitivity: ContextSensitivity,
        target: ClipboardTarget,
        profile: Profile,
        approval: ApprovalState,
    ) -> Result<(), ClipboardEgressError> {
        match self.decide(sensitivity, target, profile) {
            ClipboardDecision::Allow => Ok(()),
            ClipboardDecision::Deny => match (sensitivity, target) {
                (ContextSensitivity::TopSecret, _) => Err(ClipboardEgressError::TopSecretForbidden),
                (ContextSensitivity::Confidential, ClipboardTarget::ExternalPasteBuffer) => {
                    Err(ClipboardEgressError::ConfidentialExternalForbidden)
                }
                _ => Err(ClipboardEgressError::OperatorDeclined),
            },
            ClipboardDecision::Ask => match approval {
                ApprovalState::Approved => Ok(()),
                ApprovalState::Declined => Err(ClipboardEgressError::OperatorDeclined),
                ApprovalState::Unasked => Err(ClipboardEgressError::ApprovalRequired),
            },
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ClipboardEgressError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ClipboardEgressError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for ClipboardEgressPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ClipboardDecision::*;
    use ClipboardTarget::*;
    use ContextSensitivity::*;

    fn p() -> ClipboardEgressPolicy {
        ClipboardEgressPolicy::new()
    }

    #[test]
    fn top_secret_always_denied() {
        for t in [LocalOnly, CrossProfile, ExternalPasteBuffer] {
            for pr in [Profile::Private, Profile::Production] {
                assert_eq!(p().decide(TopSecret, t, pr), Deny);
            }
        }
    }

    #[test]
    fn confidential_external_denied() {
        assert_eq!(
            p().decide(Confidential, ExternalPasteBuffer, Profile::Private),
            Deny
        );
    }

    #[test]
    fn confidential_cross_profile_asks() {
        assert_eq!(
            p().decide(Confidential, CrossProfile, Profile::Private),
            Ask
        );
    }

    #[test]
    fn confidential_local_production_asks() {
        assert_eq!(
            p().decide(Confidential, LocalOnly, Profile::Production),
            Ask
        );
        assert_eq!(
            p().decide(Confidential, LocalOnly, Profile::Autonomous),
            Ask
        );
    }

    #[test]
    fn confidential_local_normal_allows() {
        assert_eq!(p().decide(Confidential, LocalOnly, Profile::Private), Allow);
        assert_eq!(p().decide(Confidential, LocalOnly, Profile::Fast), Allow);
    }

    #[test]
    fn internal_production_asks_off_local() {
        assert_eq!(p().decide(Internal, CrossProfile, Profile::Production), Ask);
        assert_eq!(
            p().decide(Internal, ExternalPasteBuffer, Profile::Production),
            Ask
        );
        assert_eq!(p().decide(Internal, LocalOnly, Profile::Production), Allow);
    }

    #[test]
    fn public_allows_everywhere() {
        for t in [LocalOnly, CrossProfile, ExternalPasteBuffer] {
            for pr in [Profile::Private, Profile::Production] {
                assert_eq!(p().decide(Public, t, pr), Allow);
            }
        }
    }

    #[test]
    fn gate_top_secret_returns_error() {
        assert!(matches!(
            p().gate(
                TopSecret,
                LocalOnly,
                Profile::Private,
                ApprovalState::Approved
            )
            .unwrap_err(),
            ClipboardEgressError::TopSecretForbidden
        ));
    }

    #[test]
    fn gate_confidential_external_returns_error() {
        assert!(matches!(
            p().gate(
                Confidential,
                ExternalPasteBuffer,
                Profile::Private,
                ApprovalState::Approved
            )
            .unwrap_err(),
            ClipboardEgressError::ConfidentialExternalForbidden
        ));
    }

    #[test]
    fn gate_ask_unasked_returns_approval_required() {
        assert!(matches!(
            p().gate(
                Confidential,
                CrossProfile,
                Profile::Private,
                ApprovalState::Unasked
            )
            .unwrap_err(),
            ClipboardEgressError::ApprovalRequired
        ));
    }

    #[test]
    fn gate_ask_approved_passes() {
        p().gate(
            Confidential,
            CrossProfile,
            Profile::Private,
            ApprovalState::Approved,
        )
        .unwrap();
    }

    #[test]
    fn gate_ask_declined_blocks() {
        assert!(matches!(
            p().gate(
                Confidential,
                CrossProfile,
                Profile::Private,
                ApprovalState::Declined
            )
            .unwrap_err(),
            ClipboardEgressError::OperatorDeclined
        ));
    }

    #[test]
    fn gate_public_allow_passes() {
        p().gate(
            Public,
            ExternalPasteBuffer,
            Profile::Production,
            ApprovalState::Unasked,
        )
        .unwrap();
    }

    #[test]
    fn schema_drift_rejected() {
        let mut x = p();
        x.schema_version = "9.9.9".into();
        assert!(matches!(
            x.validate().unwrap_err(),
            ClipboardEgressError::SchemaMismatch
        ));
    }

    #[test]
    fn target_serde_kebab() {
        assert_eq!(serde_json::to_string(&LocalOnly).unwrap(), "\"local-only\"");
        assert_eq!(
            serde_json::to_string(&CrossProfile).unwrap(),
            "\"cross-profile\""
        );
        assert_eq!(
            serde_json::to_string(&ExternalPasteBuffer).unwrap(),
            "\"external-paste-buffer\""
        );
    }

    #[test]
    fn sensitivity_serde_kebab() {
        assert_eq!(serde_json::to_string(&TopSecret).unwrap(), "\"top-secret\"");
    }

    #[test]
    fn policy_serde_roundtrip() {
        let x = p();
        let j = serde_json::to_string(&x).unwrap();
        let back: ClipboardEgressPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(x, back);
    }
}
