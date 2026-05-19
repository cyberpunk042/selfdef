//! `selfdef-sandbox-network-isolation` — sandbox-tier network policy.
//!
//! Each SandboxTier (0..4) declares an allowed-egress class. A
//! destination's class must be ≤ the tier's allowed class.
//!
//! * Tier0 → None (total isolation)
//! * Tier1 → LoopbackOnly
//! * Tier2 → SelectAllowlist
//! * Tier3 → SelectAllowlist (with broader allowlist)
//! * Tier4 → Broad (host-equivalent)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Sandbox tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxTier {
    /// 0 — total isolation, no network.
    Tier0,
    /// 1 — loopback only.
    Tier1,
    /// 2 — narrow allowlist.
    Tier2,
    /// 3 — broader allowlist (but still curated).
    Tier3,
    /// 4 — host-equivalent.
    Tier4,
}

/// Destination class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DestClass {
    /// In-process / no net.
    InProcess,
    /// Loopback (127.0.0.0/8, ::1).
    Loopback,
    /// LAN / private (10/8, 172.16/12, 192.168/16).
    Lan,
    /// Curated allowlist host (e.g., api.openai.com).
    AllowlistedExternal,
    /// Broad public internet.
    Public,
}

/// Decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IsolationDecision {
    /// Permitted.
    Allow,
    /// Denied — tier insufficient for destination.
    Deny,
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxNetworkIsolation {
    /// Schema version.
    pub schema_version: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum IsolationError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

impl SandboxNetworkIsolation {
    /// New canonical.
    pub fn new() -> Self {
        Self { schema_version: SCHEMA_VERSION.into() }
    }

    /// Decide given (tier, destination_class).
    pub fn decide(&self, tier: SandboxTier, dest: DestClass) -> IsolationDecision {
        let allowed_max = match tier {
            SandboxTier::Tier0 => DestClass::InProcess,
            SandboxTier::Tier1 => DestClass::Loopback,
            SandboxTier::Tier2 => DestClass::Lan,
            SandboxTier::Tier3 => DestClass::AllowlistedExternal,
            SandboxTier::Tier4 => DestClass::Public,
        };
        if dest <= allowed_max {
            IsolationDecision::Allow
        } else {
            IsolationDecision::Deny
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), IsolationError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(IsolationError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for SandboxNetworkIsolation {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> SandboxNetworkIsolation { SandboxNetworkIsolation::new() }

    #[test]
    fn tier0_only_inprocess() {
        let p = p();
        assert_eq!(p.decide(SandboxTier::Tier0, DestClass::InProcess), IsolationDecision::Allow);
        assert_eq!(p.decide(SandboxTier::Tier0, DestClass::Loopback), IsolationDecision::Deny);
    }

    #[test]
    fn tier1_loopback_ok() {
        let p = p();
        assert_eq!(p.decide(SandboxTier::Tier1, DestClass::Loopback), IsolationDecision::Allow);
        assert_eq!(p.decide(SandboxTier::Tier1, DestClass::Lan), IsolationDecision::Deny);
    }

    #[test]
    fn tier2_lan_ok() {
        let p = p();
        assert_eq!(p.decide(SandboxTier::Tier2, DestClass::Lan), IsolationDecision::Allow);
        assert_eq!(p.decide(SandboxTier::Tier2, DestClass::AllowlistedExternal), IsolationDecision::Deny);
    }

    #[test]
    fn tier3_allowlisted_ok() {
        let p = p();
        assert_eq!(p.decide(SandboxTier::Tier3, DestClass::AllowlistedExternal), IsolationDecision::Allow);
        assert_eq!(p.decide(SandboxTier::Tier3, DestClass::Public), IsolationDecision::Deny);
    }

    #[test]
    fn tier4_public_ok() {
        let p = p();
        assert_eq!(p.decide(SandboxTier::Tier4, DestClass::Public), IsolationDecision::Allow);
    }

    #[test]
    fn higher_tiers_allow_lower_classes() {
        let p = p();
        assert_eq!(p.decide(SandboxTier::Tier4, DestClass::InProcess), IsolationDecision::Allow);
        assert_eq!(p.decide(SandboxTier::Tier3, DestClass::Loopback), IsolationDecision::Allow);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut x = p();
        x.schema_version = "9.9.9".into();
        assert!(matches!(x.validate().unwrap_err(), IsolationError::SchemaMismatch));
    }

    #[test]
    fn tier_serde_kebab() {
        assert_eq!(serde_json::to_string(&SandboxTier::Tier0).unwrap(), "\"tier0\"");
        assert_eq!(serde_json::to_string(&SandboxTier::Tier4).unwrap(), "\"tier4\"");
    }

    #[test]
    fn dest_serde_kebab() {
        assert_eq!(serde_json::to_string(&DestClass::AllowlistedExternal).unwrap(), "\"allowlisted-external\"");
        assert_eq!(serde_json::to_string(&DestClass::InProcess).unwrap(), "\"in-process\"");
    }

    #[test]
    fn policy_serde_roundtrip() {
        let x = p();
        let j = serde_json::to_string(&x).unwrap();
        let back: SandboxNetworkIsolation = serde_json::from_str(&j).unwrap();
        assert_eq!(x, back);
    }
}
