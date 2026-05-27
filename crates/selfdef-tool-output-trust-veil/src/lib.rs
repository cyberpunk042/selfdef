//! `selfdef-tool-output-trust-veil` — typed wrapping of tool output.
//!
//! Wraps tool output bytes in a Veil so consumers must explicitly
//! call `unveil_with_tier(expected)` — yielding the bytes only when
//! the declared tier matches the caller's expectation. Prevents
//! implicit trust promotion across the IPS / runtime boundary.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Trust tier (mirror of llm-output-trust-tier semantics, applied
/// to tool outputs instead of LLM outputs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustTier {
    /// Verified (ground-truth checked).
    Verified,
    /// Internal (engine-owned tool).
    Internal,
    /// Untrusted (external source, web, etc.).
    Untrusted,
}

/// Wrapped output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Veil {
    /// Schema version.
    pub schema_version: String,
    /// Source tool id.
    pub source_tool: String,
    /// Declared trust tier.
    pub trust_tier: TrustTier,
    /// Bytes (UTF-8).
    pub content: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum VeilError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty source tool.
    #[error("source_tool empty")]
    EmptySourceTool,
    /// Tier mismatch on unveil.
    #[error("tier mismatch: expected {expected:?}, got {got:?}")]
    TierMismatch {
        /// expected.
        expected: TrustTier,
        /// got.
        got: TrustTier,
    },
}

impl Veil {
    /// Wrap.
    pub fn wrap(
        source_tool: &str,
        trust_tier: TrustTier,
        content: &str,
    ) -> Result<Self, VeilError> {
        if source_tool.is_empty() {
            return Err(VeilError::EmptySourceTool);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            source_tool: source_tool.into(),
            trust_tier,
            content: content.into(),
        })
    }

    /// Unveil only when expected tier matches actual. Returns content.
    pub fn unveil_with_tier(&self, expected: TrustTier) -> Result<&str, VeilError> {
        if self.trust_tier != expected {
            return Err(VeilError::TierMismatch {
                expected,
                got: self.trust_tier,
            });
        }
        Ok(self.content.as_str())
    }

    /// Unconditional tier peek (does NOT yield bytes — pure for audit).
    pub fn tier(&self) -> TrustTier {
        self.trust_tier
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), VeilError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(VeilError::SchemaMismatch);
        }
        if self.source_tool.is_empty() {
            return Err(VeilError::EmptySourceTool);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_and_unveil_matching_tier() {
        let v = Veil::wrap("git", TrustTier::Internal, "ok").unwrap();
        assert_eq!(v.unveil_with_tier(TrustTier::Internal).unwrap(), "ok");
    }

    #[test]
    fn unveil_mismatch_rejected() {
        let v = Veil::wrap("git", TrustTier::Untrusted, "hostile").unwrap();
        let err = v.unveil_with_tier(TrustTier::Verified).unwrap_err();
        assert!(matches!(err, VeilError::TierMismatch { .. }));
    }

    #[test]
    fn tier_peek_does_not_yield_bytes() {
        let v = Veil::wrap("git", TrustTier::Untrusted, "x").unwrap();
        assert_eq!(v.tier(), TrustTier::Untrusted);
        // No expose without unveil_with_tier.
    }

    #[test]
    fn empty_source_rejected() {
        assert!(matches!(
            Veil::wrap("", TrustTier::Verified, "x").unwrap_err(),
            VeilError::EmptySourceTool
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut v = Veil::wrap("git", TrustTier::Internal, "x").unwrap();
        v.schema_version = "9.9.9".into();
        assert!(matches!(
            v.validate().unwrap_err(),
            VeilError::SchemaMismatch
        ));
    }

    #[test]
    fn tier_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&TrustTier::Untrusted).unwrap(),
            "\"untrusted\""
        );
    }

    #[test]
    fn veil_serde_roundtrip() {
        let v = Veil::wrap("git", TrustTier::Internal, "ok").unwrap();
        let j = serde_json::to_string(&v).unwrap();
        let back: Veil = serde_json::from_str(&j).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn all_tiers_unveilable_with_correct_expected() {
        for t in [
            TrustTier::Verified,
            TrustTier::Internal,
            TrustTier::Untrusted,
        ] {
            let v = Veil::wrap("tool", t, "x").unwrap();
            assert!(v.unveil_with_tier(t).is_ok());
        }
    }
}
