//! `human_gate_contract` — the human-in-the-loop decision contract (MS048).
//!
//! Encodes the avx-plus-plus dump's **"The Human Gate"** verbatim (dump lines
//! 3820-3844). Where [`crate::human_gate`] is the *substrate source* (it counts
//! pending operator decisions for the scheduler's human-attention axis), this
//! is the *decision contract* — what the gate must SHOW the operator and what
//! actions they may take. The dump's doctrine (3822): *"Human-in-the-loop
//! should not be a dumb approve button."* It maps to durable execution (3846):
//! *"Pause, persist, resume."*
//!
//! What the gate shows (dump 3826-3835):
//!
//! ```text
//! what the agent wants to do / why it wants to do it / what files/tools/
//! network are involved / risk bits / expected side effects / rollback plan /
//! diff or command preview / model confidence / policy reason
//! ```
//!
//! What the operator can do (dump 3839-3845):
//!
//! ```text
//! approve / deny / edit / route to sandbox / ask oracle to review /
//! lower/raise permission
//! ```
//!
//! This realizes the peace-machine clause *"intelligence remains in the user's
//! hands"* at the decision surface. Every field + action is verbatim — none
//! invented (operator rule: "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// Doctrine (dump 3822, verbatim).
pub const DOCTRINE: &str = "Human-in-the-loop should not be a dumb approve button.";

/// Durable-execution mapping (dump 3846, verbatim).
pub const DURABLE_EXECUTION: &str = "Pause, persist, resume.";

/// The nine fields the human gate must SHOW the operator (dump 3826-3835).
pub const SHOW_FIELDS: [&str; 9] = [
    "what the agent wants to do",
    "why it wants to do it",
    "what files/tools/network are involved",
    "risk bits",
    "expected side effects",
    "rollback plan",
    "diff or command preview",
    "model confidence",
    "policy reason",
];

/// The six actions the operator may take at the gate (dump 3839-3845).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HumanGateAction {
    /// approve.
    Approve,
    /// deny.
    Deny,
    /// edit.
    Edit,
    /// route to sandbox.
    RouteToSandbox,
    /// ask oracle to review.
    AskOracleToReview,
    /// lower/raise permission.
    LowerRaisePermission,
}

impl HumanGateAction {
    /// The verbatim action label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
            Self::Edit => "edit",
            Self::RouteToSandbox => "route to sandbox",
            Self::AskOracleToReview => "ask oracle to review",
            Self::LowerRaisePermission => "lower/raise permission",
        }
    }

    /// Whether this action lets the request proceed in some form (approve /
    /// edit / route-to-sandbox / ask-oracle) vs. blocks it (deny) or only
    /// adjusts authority (lower/raise permission).
    #[must_use]
    pub const fn is_proceeding(self) -> bool {
        matches!(
            self,
            Self::Approve | Self::Edit | Self::RouteToSandbox | Self::AskOracleToReview
        )
    }
}

/// The six actions in dump order.
#[must_use]
pub fn actions() -> [HumanGateAction; 6] {
    [
        HumanGateAction::Approve,
        HumanGateAction::Deny,
        HumanGateAction::Edit,
        HumanGateAction::RouteToSandbox,
        HumanGateAction::AskOracleToReview,
        HumanGateAction::LowerRaisePermission,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nine_show_fields_verbatim() {
        assert_eq!(SHOW_FIELDS.len(), 9);
        assert_eq!(SHOW_FIELDS[0], "what the agent wants to do");
        assert_eq!(SHOW_FIELDS[8], "policy reason");
        assert!(SHOW_FIELDS.contains(&"rollback plan"));
        assert!(SHOW_FIELDS.contains(&"diff or command preview"));
    }

    #[test]
    fn six_actions_verbatim() {
        assert_eq!(HumanGateAction::Approve.label(), "approve");
        assert_eq!(HumanGateAction::RouteToSandbox.label(), "route to sandbox");
        assert_eq!(HumanGateAction::LowerRaisePermission.label(), "lower/raise permission");
        assert_eq!(actions().len(), 6);
    }

    #[test]
    fn deny_does_not_proceed() {
        assert!(!HumanGateAction::Deny.is_proceeding());
        assert!(HumanGateAction::Approve.is_proceeding());
        assert!(HumanGateAction::RouteToSandbox.is_proceeding());
    }

    #[test]
    fn actions_distinct() {
        let a = actions();
        for i in 0..6 {
            for j in (i + 1)..6 {
                assert_ne!(a[i], a[j]);
                assert_ne!(a[i].label(), a[j].label());
            }
        }
    }

    #[test]
    fn doctrines_verbatim() {
        assert_eq!(DOCTRINE, "Human-in-the-loop should not be a dumb approve button.");
        assert_eq!(DURABLE_EXECUTION, "Pause, persist, resume.");
    }

    #[test]
    fn serde_roundtrip() {
        for a in actions() {
            let j = serde_json::to_string(&a).unwrap();
            let back: HumanGateAction = serde_json::from_str(&j).unwrap();
            assert_eq!(a, back);
        }
    }
}
