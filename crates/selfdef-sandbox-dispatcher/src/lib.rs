//! `selfdef-sandbox-dispatcher` — MS036 tier selection engine.
//!
//! Given a tool descriptor, this crate selects the canonical MS036
//! sandbox tier (A/B/C/D) per E0362-E0365 + F04527 cross-cycle mapping
//! to NetworkProfile + side-effect class.
//!
//! Decision matrix per MS036 + F04527:
//! - Tier A (deterministic host tools) — read-only ops, offline profile
//! - Tier B (controlled host tools)   — fs-write, package-registries network
//! - Tier C (VM tools)                — unknown scripts, browser, docs+arbitrary
//! - Tier D (disposable microVM)      — untrusted binaries, hostile inputs
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_network_boundary::NetworkProfile;
use selfdef_policy_decision::{RiskClass, SideEffectClass};
use selfdef_sandbox_mirror::SandboxTier;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Tool descriptor input to the dispatcher.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolRequest {
    /// Canonical tool name.
    pub tool: String,
    /// Declared side-effect class.
    pub side_effect: SideEffectClass,
    /// Risk class assigned by policy.
    pub risk: RiskClass,
    /// Required network profile.
    pub network: NetworkProfile,
    /// Whether the operator has signed approval.
    pub operator_approved: bool,
    /// Whether the tool is in the trusted-tools registry.
    pub trusted: bool,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DispatchError {
    /// Tool name empty.
    #[error("tool name empty")]
    EmptyTool,
    /// Untrusted tool routed Tier C/D without operator approval.
    #[error("untrusted tool {tool} requires operator approval before {tier:?}")]
    UntrustedNeedsApproval {
        /// Tool name.
        tool: String,
        /// Tier dispatcher wanted to assign.
        tier: SandboxTier,
    },
    /// Combination is impossible (e.g. Critical risk + Offline network).
    #[error("impossible request: {0}")]
    ImpossibleCombination(String),
}

/// Decide the MS036 tier for a tool request.
pub fn dispatch(req: &ToolRequest) -> Result<SandboxTier, DispatchError> {
    if req.tool.is_empty() {
        return Err(DispatchError::EmptyTool);
    }

    // Critical risk always pins to Tier D regardless of trust.
    if req.risk == RiskClass::Critical {
        if !req.operator_approved {
            return Err(DispatchError::UntrustedNeedsApproval {
                tool: req.tool.clone(),
                tier: SandboxTier::TierD,
            });
        }
        return Ok(SandboxTier::TierD);
    }

    // Untrusted tools never run on Tier A regardless of side-effect.
    if !req.trusted {
        let want = if req.side_effect == SideEffectClass::ReadOnly
            && req.network == NetworkProfile::Offline
        {
            SandboxTier::TierB
        } else if req.network == NetworkProfile::AuthenticatedBrowser {
            SandboxTier::TierD
        } else {
            SandboxTier::TierC
        };
        if !req.operator_approved {
            return Err(DispatchError::UntrustedNeedsApproval {
                tool: req.tool.clone(),
                tier: want,
            });
        }
        return Ok(want);
    }

    // Trusted-tool dispatch: walk side-effect + network.
    let tier = match (req.side_effect, req.network) {
        // Pure read-only + offline → Tier A.
        (SideEffectClass::None | SideEffectClass::ReadOnly, NetworkProfile::Offline) => {
            SandboxTier::TierA
        }
        // Read-only + any-network → Tier B.
        (SideEffectClass::ReadOnly, _) => SandboxTier::TierB,
        // Filesystem write, package-registries → Tier B.
        (SideEffectClass::FsWrite, NetworkProfile::Offline | NetworkProfile::PackageRegistries) => {
            SandboxTier::TierB
        }
        // Filesystem write + docs/arbitrary/authenticated → Tier C.
        (SideEffectClass::FsWrite, _) => SandboxTier::TierC,
        // Network egress + non-offline → Tier B (package-registries) or Tier C (docs+) or Tier D (authenticated).
        (SideEffectClass::NetworkEgress, NetworkProfile::Offline) => {
            return Err(DispatchError::ImpossibleCombination(
                "NetworkEgress side-effect with Offline network".into(),
            ));
        }
        (SideEffectClass::NetworkEgress, NetworkProfile::PackageRegistries) => SandboxTier::TierB,
        (
            SideEffectClass::NetworkEgress,
            NetworkProfile::DocsOnly | NetworkProfile::ArbitraryWeb,
        ) => SandboxTier::TierC,
        (SideEffectClass::NetworkEgress, NetworkProfile::AuthenticatedBrowser) => {
            SandboxTier::TierC
        }
        // Process spawn → Tier C (or D when high-risk).
        (SideEffectClass::Process, _) => {
            if req.risk == RiskClass::High {
                SandboxTier::TierD
            } else {
                SandboxTier::TierC
            }
        }
        // Persistent change — should already have been L5/L6-gated; default Tier B + operator approval.
        (SideEffectClass::Persistent, _) => {
            if !req.operator_approved {
                return Err(DispatchError::UntrustedNeedsApproval {
                    tool: req.tool.clone(),
                    tier: SandboxTier::TierB,
                });
            }
            SandboxTier::TierB
        }
        // None side-effect + non-offline network — Tier B (still bounded).
        (SideEffectClass::None, _) => SandboxTier::TierB,
    };

    Ok(tier)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> ToolRequest {
        ToolRequest {
            tool: "rg".into(),
            side_effect: SideEffectClass::ReadOnly,
            risk: RiskClass::Low,
            network: NetworkProfile::Offline,
            operator_approved: false,
            trusted: true,
        }
    }

    #[test]
    fn empty_tool_rejected() {
        let mut r = req();
        r.tool = String::new();
        assert!(matches!(
            dispatch(&r).unwrap_err(),
            DispatchError::EmptyTool
        ));
    }

    #[test]
    fn trusted_readonly_offline_lands_tier_a() {
        assert_eq!(dispatch(&req()).unwrap(), SandboxTier::TierA);
    }

    #[test]
    fn trusted_readonly_with_network_lands_tier_b() {
        let mut r = req();
        r.network = NetworkProfile::PackageRegistries;
        assert_eq!(dispatch(&r).unwrap(), SandboxTier::TierB);
    }

    #[test]
    fn trusted_fs_write_offline_or_package_lands_tier_b() {
        let mut r = req();
        r.side_effect = SideEffectClass::FsWrite;
        r.network = NetworkProfile::Offline;
        assert_eq!(dispatch(&r).unwrap(), SandboxTier::TierB);
        r.network = NetworkProfile::PackageRegistries;
        assert_eq!(dispatch(&r).unwrap(), SandboxTier::TierB);
    }

    #[test]
    fn trusted_fs_write_authenticated_lands_tier_c() {
        let mut r = req();
        r.side_effect = SideEffectClass::FsWrite;
        r.network = NetworkProfile::AuthenticatedBrowser;
        assert_eq!(dispatch(&r).unwrap(), SandboxTier::TierC);
    }

    #[test]
    fn network_egress_offline_impossible() {
        let mut r = req();
        r.side_effect = SideEffectClass::NetworkEgress;
        r.network = NetworkProfile::Offline;
        assert!(matches!(
            dispatch(&r).unwrap_err(),
            DispatchError::ImpossibleCombination(_)
        ));
    }

    #[test]
    fn network_egress_package_lands_tier_b() {
        let mut r = req();
        r.side_effect = SideEffectClass::NetworkEgress;
        r.network = NetworkProfile::PackageRegistries;
        assert_eq!(dispatch(&r).unwrap(), SandboxTier::TierB);
    }

    #[test]
    fn process_spawn_high_risk_lands_tier_d() {
        let mut r = req();
        r.side_effect = SideEffectClass::Process;
        r.risk = RiskClass::High;
        assert_eq!(dispatch(&r).unwrap(), SandboxTier::TierD);
    }

    #[test]
    fn process_spawn_low_risk_lands_tier_c() {
        let mut r = req();
        r.side_effect = SideEffectClass::Process;
        r.risk = RiskClass::Low;
        assert_eq!(dispatch(&r).unwrap(), SandboxTier::TierC);
    }

    #[test]
    fn persistent_side_effect_needs_approval() {
        let mut r = req();
        r.side_effect = SideEffectClass::Persistent;
        r.operator_approved = false;
        assert!(matches!(
            dispatch(&r).unwrap_err(),
            DispatchError::UntrustedNeedsApproval { .. }
        ));
        r.operator_approved = true;
        assert_eq!(dispatch(&r).unwrap(), SandboxTier::TierB);
    }

    #[test]
    fn untrusted_tool_unapproved_refused() {
        let mut r = req();
        r.trusted = false;
        r.operator_approved = false;
        assert!(matches!(
            dispatch(&r).unwrap_err(),
            DispatchError::UntrustedNeedsApproval { .. }
        ));
    }

    #[test]
    fn untrusted_tool_approved_lands_tier_b_when_safe() {
        let mut r = req();
        r.trusted = false;
        r.operator_approved = true;
        // readonly + offline → Tier B (not Tier A, since untrusted)
        assert_eq!(dispatch(&r).unwrap(), SandboxTier::TierB);
    }

    #[test]
    fn untrusted_tool_with_authenticated_lands_tier_d() {
        let mut r = req();
        r.trusted = false;
        r.operator_approved = true;
        r.network = NetworkProfile::AuthenticatedBrowser;
        assert_eq!(dispatch(&r).unwrap(), SandboxTier::TierD);
    }

    #[test]
    fn critical_risk_lands_tier_d_with_approval() {
        let mut r = req();
        r.risk = RiskClass::Critical;
        r.operator_approved = true;
        assert_eq!(dispatch(&r).unwrap(), SandboxTier::TierD);
    }

    #[test]
    fn critical_risk_unapproved_refused() {
        let mut r = req();
        r.risk = RiskClass::Critical;
        r.operator_approved = false;
        assert!(matches!(
            dispatch(&r).unwrap_err(),
            DispatchError::UntrustedNeedsApproval { .. }
        ));
    }
}
