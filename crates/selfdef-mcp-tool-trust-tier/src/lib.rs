//! `selfdef-mcp-tool-trust-tier` — per-tool trust tier + per-Profile floor.
//!
//! Each MCP tool is registered at a `TrustTier`:
//!
//!   Sandbox < SemiTrusted < Trusted < Hardened
//!
//! Each Profile carries a `minimum_tier`. `classify(profile, tool)`
//! returns Allowed when tool tier >= profile minimum, else
//! `BelowTier{needed, got}`.
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

/// Trust tier (ordering: Sandbox < SemiTrusted < Trusted < Hardened).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustTier {
    /// Sandboxed third-party tool.
    Sandbox,
    /// Reviewed but third-party.
    SemiTrusted,
    /// First-party + reviewed.
    Trusted,
    /// First-party + signed + audited.
    Hardened,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpToolTrustTier {
    /// Schema version.
    pub schema_version: String,
    /// Tool tier registry.
    pub tools: BTreeMap<String, TrustTier>,
    /// Per-profile minimum tier.
    pub minimum_tier: BTreeMap<Profile, TrustTier>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum TierVerdict {
    /// Allowed.
    Allowed,
    /// Below floor.
    BelowTier {
        /// Needed tier.
        needed: TrustTier,
        /// Observed.
        got: TrustTier,
    },
    /// Tool not registered.
    UnknownTool,
    /// Profile unconfigured.
    Unconfigured,
}

/// Errors.
#[derive(Debug, Error)]
pub enum TierError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty tool id.
    #[error("tool id empty")]
    EmptyId,
}

impl McpToolTrustTier {
    /// New.
    pub fn new() -> Self {
        let mut min = BTreeMap::new();
        min.insert(Profile::Private, TrustTier::Trusted);
        min.insert(Profile::Fast, TrustTier::SemiTrusted);
        min.insert(Profile::Careful, TrustTier::Trusted);
        min.insert(Profile::Autonomous, TrustTier::SemiTrusted);
        min.insert(Profile::Experimental, TrustTier::Sandbox);
        min.insert(Profile::Production, TrustTier::Hardened);
        Self {
            schema_version: SCHEMA_VERSION.into(),
            tools: BTreeMap::new(),
            minimum_tier: min,
        }
    }

    /// Register a tool.
    pub fn register(&mut self, tool_id: &str, tier: TrustTier) -> Result<(), TierError> {
        if tool_id.is_empty() {
            return Err(TierError::EmptyId);
        }
        self.tools.insert(tool_id.into(), tier);
        Ok(())
    }

    /// Classify.
    pub fn classify(&self, profile: Profile, tool_id: &str) -> TierVerdict {
        let got = match self.tools.get(tool_id) {
            Some(&t) => t,
            None => return TierVerdict::UnknownTool,
        };
        let needed = match self.minimum_tier.get(&profile) {
            Some(&t) => t,
            None => return TierVerdict::Unconfigured,
        };
        if got >= needed {
            TierVerdict::Allowed
        } else {
            TierVerdict::BelowTier { needed, got }
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), TierError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(TierError::SchemaMismatch);
        }
        for id in self.tools.keys() {
            if id.is_empty() {
                return Err(TierError::EmptyId);
            }
        }
        Ok(())
    }
}

impl Default for McpToolTrustTier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering() {
        assert!(TrustTier::Sandbox < TrustTier::SemiTrusted);
        assert!(TrustTier::SemiTrusted < TrustTier::Trusted);
        assert!(TrustTier::Trusted < TrustTier::Hardened);
    }

    #[test]
    fn register_and_classify_allowed() {
        let mut t = McpToolTrustTier::new();
        t.register("read-file", TrustTier::Hardened).unwrap();
        assert_eq!(
            t.classify(Profile::Production, "read-file"),
            TierVerdict::Allowed
        );
    }

    #[test]
    fn below_tier() {
        let mut t = McpToolTrustTier::new();
        t.register("scratch", TrustTier::Sandbox).unwrap();
        let v = t.classify(Profile::Production, "scratch");
        match v {
            TierVerdict::BelowTier { needed, got } => {
                assert_eq!(needed, TrustTier::Hardened);
                assert_eq!(got, TrustTier::Sandbox);
            }
            _ => panic!("expected below-tier"),
        }
    }

    #[test]
    fn experimental_admits_sandbox() {
        let mut t = McpToolTrustTier::new();
        t.register("hack", TrustTier::Sandbox).unwrap();
        assert_eq!(
            t.classify(Profile::Experimental, "hack"),
            TierVerdict::Allowed
        );
    }

    #[test]
    fn unknown_tool() {
        let t = McpToolTrustTier::new();
        assert_eq!(t.classify(Profile::Fast, "nope"), TierVerdict::UnknownTool);
    }

    #[test]
    fn unconfigured_profile() {
        let mut t = McpToolTrustTier::new();
        t.register("read-file", TrustTier::Hardened).unwrap();
        t.minimum_tier.clear();
        assert_eq!(
            t.classify(Profile::Production, "read-file"),
            TierVerdict::Unconfigured
        );
    }

    #[test]
    fn empty_id_rejected() {
        let mut t = McpToolTrustTier::new();
        assert!(matches!(
            t.register("", TrustTier::Sandbox).unwrap_err(),
            TierError::EmptyId
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = McpToolTrustTier::new();
        t.schema_version = "9.9.9".into();
        assert!(matches!(
            t.validate().unwrap_err(),
            TierError::SchemaMismatch
        ));
    }

    #[test]
    fn tier_serde_roundtrip() {
        let mut t = McpToolTrustTier::new();
        t.register("read-file", TrustTier::Trusted).unwrap();
        let j = serde_json::to_string(&t).unwrap();
        let back: McpToolTrustTier = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
