//! `selfdef-sandbox-tier-policy` — IPS authority over sandbox tiers.
//!
//! 5 tiers Tier0..Tier4 (ascending capability). Each tier declares
//! capability deltas; the authority owns promotion/demotion gates
//! (e.g. Tier0→Tier1 always operator-explicit; Tier3→Tier4 requires
//! double-operator).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// 5 sandbox tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxTier {
    /// Tier 0 — pure read-only observe.
    Tier0,
    /// Tier 1 — minimal capabilities.
    Tier1,
    /// Tier 2 — chroot, no host fs writes, no network.
    Tier2,
    /// Tier 3 — controlled network egress allowed.
    Tier3,
    /// Tier 4 — full sandbox with persistent state.
    Tier4,
}

/// Capability tuple per tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierCapabilities {
    /// Sub-process spawn allowed.
    pub subprocess_allowed: bool,
    /// Network egress allowed.
    pub network_allowed: bool,
    /// Persistent state (writes survive sandbox teardown) allowed.
    pub persistent_allowed: bool,
    /// Host filesystem readable (read-only mount).
    pub host_fs_readable: bool,
}

/// Promotion gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PromotionGate {
    /// Routine — no extra check (typically demotion).
    Routine,
    /// Single-operator approval.
    SingleOperator,
    /// Double-operator approval (two distinct MS003 signatures).
    DoubleOperator,
    /// Forbidden.
    Forbidden,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SandboxTierError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Self-transition.
    #[error("self-transition {0:?}")]
    SelfTransition(SandboxTier),
    /// Forbidden transition.
    #[error("transition {from:?} -> {to:?} is forbidden")]
    Forbidden {
        /// from.
        from: SandboxTier,
        /// to.
        to: SandboxTier,
    },
    /// Missing operator approval.
    #[error("transition {from:?} -> {to:?} requires {required:?} approvals; got {got}")]
    MissingApproval {
        /// from.
        from: SandboxTier,
        /// to.
        to: SandboxTier,
        /// required.
        required: PromotionGate,
        /// got.
        got: u8,
    },
}

impl SandboxTier {
    /// All 5.
    pub const ALL: [SandboxTier; 5] = [
        SandboxTier::Tier0,
        SandboxTier::Tier1,
        SandboxTier::Tier2,
        SandboxTier::Tier3,
        SandboxTier::Tier4,
    ];

    /// Capabilities at this tier.
    pub fn capabilities(self) -> TierCapabilities {
        match self {
            SandboxTier::Tier0 => TierCapabilities {
                subprocess_allowed: false,
                network_allowed: false,
                persistent_allowed: false,
                host_fs_readable: false,
            },
            SandboxTier::Tier1 => TierCapabilities {
                subprocess_allowed: false,
                network_allowed: false,
                persistent_allowed: false,
                host_fs_readable: true,
            },
            SandboxTier::Tier2 => TierCapabilities {
                subprocess_allowed: true,
                network_allowed: false,
                persistent_allowed: false,
                host_fs_readable: true,
            },
            SandboxTier::Tier3 => TierCapabilities {
                subprocess_allowed: true,
                network_allowed: true,
                persistent_allowed: false,
                host_fs_readable: true,
            },
            SandboxTier::Tier4 => TierCapabilities {
                subprocess_allowed: true,
                network_allowed: true,
                persistent_allowed: true,
                host_fs_readable: true,
            },
        }
    }
}

/// IPS-authoritative gate for a (from, to) tier transition.
pub fn promotion_gate(from: SandboxTier, to: SandboxTier) -> PromotionGate {
    if from == to {
        return PromotionGate::Routine;
    }
    // Demotion always routine.
    if (to as u8) < (from as u8) {
        return PromotionGate::Routine;
    }
    // Promotion: tier0→1 single, 1→2 single, 2→3 single, 3→4 double.
    let delta = (to as u8).wrapping_sub(from as u8);
    if delta > 1 {
        return PromotionGate::Forbidden;
    } // no skipping
    match to {
        SandboxTier::Tier4 => PromotionGate::DoubleOperator,
        _ => PromotionGate::SingleOperator,
    }
}

/// Authorize a tier transition with N operator signatures available.
pub fn authorize_promotion(
    from: SandboxTier,
    to: SandboxTier,
    operator_signatures: u8,
) -> Result<(), SandboxTierError> {
    if from == to {
        return Err(SandboxTierError::SelfTransition(from));
    }
    match promotion_gate(from, to) {
        PromotionGate::Routine => Ok(()),
        PromotionGate::Forbidden => Err(SandboxTierError::Forbidden { from, to }),
        PromotionGate::SingleOperator => {
            if operator_signatures < 1 {
                Err(SandboxTierError::MissingApproval {
                    from,
                    to,
                    required: PromotionGate::SingleOperator,
                    got: operator_signatures,
                })
            } else {
                Ok(())
            }
        }
        PromotionGate::DoubleOperator => {
            if operator_signatures < 2 {
                Err(SandboxTierError::MissingApproval {
                    from,
                    to,
                    required: PromotionGate::DoubleOperator,
                    got: operator_signatures,
                })
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_tiers_ordered() {
        let v = SandboxTier::ALL;
        for w in v.windows(2) {
            assert!(w[0] < w[1]);
        }
    }

    #[test]
    fn tier0_no_capabilities() {
        let c = SandboxTier::Tier0.capabilities();
        assert!(!c.subprocess_allowed);
        assert!(!c.network_allowed);
        assert!(!c.persistent_allowed);
        assert!(!c.host_fs_readable);
    }

    #[test]
    fn tier4_max_capabilities() {
        let c = SandboxTier::Tier4.capabilities();
        assert!(c.subprocess_allowed);
        assert!(c.network_allowed);
        assert!(c.persistent_allowed);
        assert!(c.host_fs_readable);
    }

    #[test]
    fn promotion_one_step_single_operator() {
        assert_eq!(
            promotion_gate(SandboxTier::Tier0, SandboxTier::Tier1),
            PromotionGate::SingleOperator
        );
        assert_eq!(
            promotion_gate(SandboxTier::Tier1, SandboxTier::Tier2),
            PromotionGate::SingleOperator
        );
        assert_eq!(
            promotion_gate(SandboxTier::Tier2, SandboxTier::Tier3),
            PromotionGate::SingleOperator
        );
    }

    #[test]
    fn tier3_to_tier4_double_operator() {
        assert_eq!(
            promotion_gate(SandboxTier::Tier3, SandboxTier::Tier4),
            PromotionGate::DoubleOperator
        );
    }

    #[test]
    fn skipping_tiers_forbidden() {
        assert_eq!(
            promotion_gate(SandboxTier::Tier0, SandboxTier::Tier2),
            PromotionGate::Forbidden
        );
        assert_eq!(
            promotion_gate(SandboxTier::Tier1, SandboxTier::Tier4),
            PromotionGate::Forbidden
        );
    }

    #[test]
    fn demotion_routine() {
        assert_eq!(
            promotion_gate(SandboxTier::Tier4, SandboxTier::Tier0),
            PromotionGate::Routine
        );
        assert_eq!(
            promotion_gate(SandboxTier::Tier2, SandboxTier::Tier1),
            PromotionGate::Routine
        );
    }

    #[test]
    fn authorize_promotion_zero_sigs_rejected() {
        assert!(matches!(
            authorize_promotion(SandboxTier::Tier0, SandboxTier::Tier1, 0).unwrap_err(),
            SandboxTierError::MissingApproval { .. }
        ));
    }

    #[test]
    fn authorize_promotion_one_sig_works_for_single() {
        authorize_promotion(SandboxTier::Tier0, SandboxTier::Tier1, 1).unwrap();
    }

    #[test]
    fn authorize_promotion_one_sig_rejected_for_double() {
        assert!(matches!(
            authorize_promotion(SandboxTier::Tier3, SandboxTier::Tier4, 1).unwrap_err(),
            SandboxTierError::MissingApproval { .. }
        ));
        authorize_promotion(SandboxTier::Tier3, SandboxTier::Tier4, 2).unwrap();
    }

    #[test]
    fn skip_tier_promotion_forbidden() {
        assert!(matches!(
            authorize_promotion(SandboxTier::Tier0, SandboxTier::Tier3, 99).unwrap_err(),
            SandboxTierError::Forbidden { .. }
        ));
    }

    #[test]
    fn demotion_no_sigs_required() {
        authorize_promotion(SandboxTier::Tier4, SandboxTier::Tier0, 0).unwrap();
    }

    #[test]
    fn self_transition_rejected() {
        assert!(matches!(
            authorize_promotion(SandboxTier::Tier2, SandboxTier::Tier2, 1).unwrap_err(),
            SandboxTierError::SelfTransition(SandboxTier::Tier2)
        ));
    }

    #[test]
    fn tier_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&SandboxTier::Tier0).unwrap(),
            "\"tier0\""
        );
        assert_eq!(
            serde_json::to_string(&SandboxTier::Tier4).unwrap(),
            "\"tier4\""
        );
    }
}
