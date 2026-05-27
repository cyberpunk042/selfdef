//! `selfdef-action-confirmation-tier` — confirmation gesture authority.
//!
//! Each BlastRadius maps to a required ConfirmationTier:
//! * LocalEphemeral → None
//! * LocalPersistent → SingleClick
//! * CrossSession → TypedConfirm ("yes")
//! * CrossMachine → TypedConfirm ("CONFIRM")
//! * Public → TypedName (must match action's expected_name)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Blast radius (mirror of selfdef-blast-radius-classifier).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlastRadius {
    /// Local ephemeral.
    LocalEphemeral,
    /// Local persistent.
    LocalPersistent,
    /// Cross-session.
    CrossSession,
    /// Cross-machine.
    CrossMachine,
    /// Public.
    Public,
}

/// Required confirmation tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfirmationTier {
    /// None.
    None,
    /// SingleClick (a Yes button).
    SingleClick,
    /// TypedConfirm (operator types "yes" / "CONFIRM").
    TypedConfirm,
    /// TypedName (operator types the action's specific expected_name).
    TypedName,
}

/// Operator-supplied input.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum OperatorInput {
    /// Nothing supplied.
    Empty,
    /// Operator clicked the yes button.
    Click,
    /// Operator typed something.
    Typed {
        /// the typed text.
        text: String,
    },
}

/// Decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GateDecision {
    /// Allowed (confirmation matched).
    Allow,
    /// Confirmation required but absent/wrong.
    Deny,
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionConfirmationTier {
    /// Schema version.
    pub schema_version: String,
    /// Cross-machine typed-confirm expected text.
    pub cross_machine_confirm_text: String,
    /// Cross-session typed-confirm expected text.
    pub cross_session_confirm_text: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ConfirmError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty expected text.
    #[error("confirm text empty")]
    EmptyConfirmText,
}

impl ActionConfirmationTier {
    /// Canonical: cross_session="yes", cross_machine="CONFIRM".
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            cross_machine_confirm_text: "CONFIRM".into(),
            cross_session_confirm_text: "yes".into(),
        }
    }

    /// Required tier for radius.
    pub fn required_tier(&self, r: BlastRadius) -> ConfirmationTier {
        match r {
            BlastRadius::LocalEphemeral => ConfirmationTier::None,
            BlastRadius::LocalPersistent => ConfirmationTier::SingleClick,
            BlastRadius::CrossSession => ConfirmationTier::TypedConfirm,
            BlastRadius::CrossMachine => ConfirmationTier::TypedConfirm,
            BlastRadius::Public => ConfirmationTier::TypedName,
        }
    }

    /// Gate. `expected_name` is the action's specific name required at TypedName tier.
    pub fn gate(
        &self,
        radius: BlastRadius,
        input: &OperatorInput,
        expected_name: &str,
    ) -> GateDecision {
        match self.required_tier(radius) {
            ConfirmationTier::None => GateDecision::Allow,
            ConfirmationTier::SingleClick => {
                if matches!(input, OperatorInput::Click) {
                    GateDecision::Allow
                } else {
                    GateDecision::Deny
                }
            }
            ConfirmationTier::TypedConfirm => {
                let need = match radius {
                    BlastRadius::CrossSession => self.cross_session_confirm_text.as_str(),
                    BlastRadius::CrossMachine => self.cross_machine_confirm_text.as_str(),
                    _ => return GateDecision::Deny,
                };
                match input {
                    OperatorInput::Typed { text } if text == need => GateDecision::Allow,
                    _ => GateDecision::Deny,
                }
            }
            ConfirmationTier::TypedName => match input {
                OperatorInput::Typed { text } if text == expected_name => GateDecision::Allow,
                _ => GateDecision::Deny,
            },
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ConfirmError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ConfirmError::SchemaMismatch);
        }
        if self.cross_machine_confirm_text.is_empty() || self.cross_session_confirm_text.is_empty()
        {
            return Err(ConfirmError::EmptyConfirmText);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        ActionConfirmationTier::canonical().validate().unwrap();
    }

    #[test]
    fn local_ephemeral_no_confirm() {
        let p = ActionConfirmationTier::canonical();
        assert_eq!(
            p.gate(BlastRadius::LocalEphemeral, &OperatorInput::Empty, ""),
            GateDecision::Allow
        );
    }

    #[test]
    fn local_persistent_requires_click() {
        let p = ActionConfirmationTier::canonical();
        assert_eq!(
            p.gate(BlastRadius::LocalPersistent, &OperatorInput::Empty, ""),
            GateDecision::Deny
        );
        assert_eq!(
            p.gate(BlastRadius::LocalPersistent, &OperatorInput::Click, ""),
            GateDecision::Allow
        );
    }

    #[test]
    fn cross_session_yes_required() {
        let p = ActionConfirmationTier::canonical();
        assert_eq!(
            p.gate(BlastRadius::CrossSession, &OperatorInput::Click, ""),
            GateDecision::Deny
        );
        assert_eq!(
            p.gate(
                BlastRadius::CrossSession,
                &OperatorInput::Typed { text: "yes".into() },
                ""
            ),
            GateDecision::Allow
        );
        assert_eq!(
            p.gate(
                BlastRadius::CrossSession,
                &OperatorInput::Typed { text: "no".into() },
                ""
            ),
            GateDecision::Deny
        );
    }

    #[test]
    fn cross_machine_confirm_required() {
        let p = ActionConfirmationTier::canonical();
        assert_eq!(
            p.gate(
                BlastRadius::CrossMachine,
                &OperatorInput::Typed { text: "yes".into() },
                ""
            ),
            GateDecision::Deny
        );
        assert_eq!(
            p.gate(
                BlastRadius::CrossMachine,
                &OperatorInput::Typed {
                    text: "CONFIRM".into()
                },
                ""
            ),
            GateDecision::Allow
        );
    }

    #[test]
    fn public_typed_name_required() {
        let p = ActionConfirmationTier::canonical();
        assert_eq!(
            p.gate(
                BlastRadius::Public,
                &OperatorInput::Typed {
                    text: "wrong".into()
                },
                "delete-prod"
            ),
            GateDecision::Deny
        );
        assert_eq!(
            p.gate(
                BlastRadius::Public,
                &OperatorInput::Typed {
                    text: "delete-prod".into()
                },
                "delete-prod"
            ),
            GateDecision::Allow
        );
    }

    #[test]
    fn empty_input_denies_high_tiers() {
        let p = ActionConfirmationTier::canonical();
        for r in [
            BlastRadius::CrossSession,
            BlastRadius::CrossMachine,
            BlastRadius::Public,
        ] {
            assert_eq!(p.gate(r, &OperatorInput::Empty, "x"), GateDecision::Deny);
        }
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = ActionConfirmationTier::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            ConfirmError::SchemaMismatch
        ));
    }

    #[test]
    fn empty_confirm_text_rejected() {
        let mut p = ActionConfirmationTier::canonical();
        p.cross_machine_confirm_text = String::new();
        assert!(matches!(
            p.validate().unwrap_err(),
            ConfirmError::EmptyConfirmText
        ));
    }

    #[test]
    fn tier_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&ConfirmationTier::SingleClick).unwrap(),
            "\"single-click\""
        );
        assert_eq!(
            serde_json::to_string(&ConfirmationTier::TypedName).unwrap(),
            "\"typed-name\""
        );
    }

    #[test]
    fn input_serde_kebab() {
        let t = OperatorInput::Typed { text: "x".into() };
        assert!(
            serde_json::to_string(&t)
                .unwrap()
                .contains("\"kind\":\"typed\"")
        );
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = ActionConfirmationTier::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: ActionConfirmationTier = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
