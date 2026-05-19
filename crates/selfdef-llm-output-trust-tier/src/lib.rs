//! `selfdef-llm-output-trust-tier` — LLM-output trust classifier.
//!
//! Each artifact is rated by (provider tier, ground-truth check
//! pass/fail, consensus count) → TrustTier. Downstream gates use
//! the tier to gate autonomous execution / verbatim display.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Provider trust tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderTier {
    /// Local model on the operator's hardware.
    LocalSubstrate,
    /// Vendor model on cloud.
    Vendor,
    /// Open-weights model from external.
    OpenWeights,
    /// Untrusted / community.
    Untrusted,
}

/// Ground-truth result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroundTruth {
    /// Passed an automated correctness check (tests, parser, etc.).
    Passed,
    /// Failed an automated check.
    Failed,
    /// No automated check applicable.
    Skipped,
}

/// Trust tier (output).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustTier {
    /// Verified by ground truth, may execute autonomously.
    Verified,
    /// Corroborated by ≥ 2 distinct providers, may execute with logging.
    Corroborated,
    /// Single source, no verification — requires operator approval.
    Unverified,
    /// Failed verification — quarantine.
    Contradicted,
}

/// Input.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactFeatures {
    /// Provider that produced the artifact.
    pub provider: ProviderTier,
    /// Ground-truth check result.
    pub ground_truth: GroundTruth,
    /// How many distinct providers produced the same artifact (≥ 1).
    pub consensus_count: u8,
}

/// Classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustClassification {
    /// Schema version.
    pub schema_version: String,
    /// Tier.
    pub tier: TrustTier,
    /// Reason notes.
    pub notes: Vec<String>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum TrustError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// consensus_count zero.
    #[error("consensus_count is zero")]
    ConsensusZero,
}

/// Pure classifier.
#[derive(Debug, Clone, Default)]
pub struct LlmOutputTrustClassifier;

impl LlmOutputTrustClassifier {
    /// Classify.
    pub fn classify(f: ArtifactFeatures) -> Result<TrustClassification, TrustError> {
        if f.consensus_count == 0 {
            return Err(TrustError::ConsensusZero);
        }
        let mut notes: Vec<String> = Vec::new();
        // Failed ground truth → Contradicted always.
        if f.ground_truth == GroundTruth::Failed {
            notes.push("ground-truth failed".into());
            return Ok(TrustClassification {
                schema_version: SCHEMA_VERSION.into(),
                tier: TrustTier::Contradicted,
                notes,
            });
        }
        // Passed ground truth → Verified.
        if f.ground_truth == GroundTruth::Passed {
            notes.push("ground-truth passed".into());
            return Ok(TrustClassification {
                schema_version: SCHEMA_VERSION.into(),
                tier: TrustTier::Verified,
                notes,
            });
        }
        // Skipped ground truth: trust based on consensus + provider.
        if f.consensus_count >= 2 {
            notes.push(format!("consensus {} providers", f.consensus_count));
            return Ok(TrustClassification {
                schema_version: SCHEMA_VERSION.into(),
                tier: TrustTier::Corroborated,
                notes,
            });
        }
        // Single source: tier depends on provider.
        let tier = match f.provider {
            ProviderTier::LocalSubstrate => {
                notes.push("local substrate, ground truth skipped".into());
                TrustTier::Unverified
            }
            ProviderTier::Vendor => {
                notes.push("vendor, ground truth skipped".into());
                TrustTier::Unverified
            }
            ProviderTier::OpenWeights => {
                notes.push("open-weights, ground truth skipped".into());
                TrustTier::Unverified
            }
            ProviderTier::Untrusted => {
                notes.push("untrusted provider".into());
                TrustTier::Contradicted
            }
        };
        Ok(TrustClassification {
            schema_version: SCHEMA_VERSION.into(),
            tier,
            notes,
        })
    }
}

impl TrustClassification {
    /// Validate.
    pub fn validate(&self) -> Result<(), TrustError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(TrustError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feat(p: ProviderTier, g: GroundTruth, n: u8) -> ArtifactFeatures {
        ArtifactFeatures { provider: p, ground_truth: g, consensus_count: n }
    }

    #[test]
    fn consensus_zero_rejected() {
        assert!(matches!(
            LlmOutputTrustClassifier::classify(feat(ProviderTier::Vendor, GroundTruth::Skipped, 0)).unwrap_err(),
            TrustError::ConsensusZero
        ));
    }

    #[test]
    fn ground_truth_passed_is_verified() {
        let c = LlmOutputTrustClassifier::classify(feat(ProviderTier::Untrusted, GroundTruth::Passed, 1)).unwrap();
        assert_eq!(c.tier, TrustTier::Verified);
    }

    #[test]
    fn ground_truth_failed_is_contradicted() {
        let c = LlmOutputTrustClassifier::classify(feat(ProviderTier::LocalSubstrate, GroundTruth::Failed, 5)).unwrap();
        assert_eq!(c.tier, TrustTier::Contradicted);
    }

    #[test]
    fn consensus_two_or_more_is_corroborated() {
        let c = LlmOutputTrustClassifier::classify(feat(ProviderTier::Vendor, GroundTruth::Skipped, 2)).unwrap();
        assert_eq!(c.tier, TrustTier::Corroborated);
    }

    #[test]
    fn single_source_vendor_is_unverified() {
        let c = LlmOutputTrustClassifier::classify(feat(ProviderTier::Vendor, GroundTruth::Skipped, 1)).unwrap();
        assert_eq!(c.tier, TrustTier::Unverified);
    }

    #[test]
    fn single_source_local_is_unverified() {
        let c = LlmOutputTrustClassifier::classify(feat(ProviderTier::LocalSubstrate, GroundTruth::Skipped, 1)).unwrap();
        assert_eq!(c.tier, TrustTier::Unverified);
    }

    #[test]
    fn single_source_untrusted_is_contradicted() {
        let c = LlmOutputTrustClassifier::classify(feat(ProviderTier::Untrusted, GroundTruth::Skipped, 1)).unwrap();
        assert_eq!(c.tier, TrustTier::Contradicted);
    }

    #[test]
    fn untrusted_with_passed_still_verified() {
        // ground-truth-pass dominates.
        let c = LlmOutputTrustClassifier::classify(feat(ProviderTier::Untrusted, GroundTruth::Passed, 1)).unwrap();
        assert_eq!(c.tier, TrustTier::Verified);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = LlmOutputTrustClassifier::classify(feat(ProviderTier::Vendor, GroundTruth::Passed, 1)).unwrap();
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), TrustError::SchemaMismatch));
    }

    #[test]
    fn tier_serde_kebab() {
        assert_eq!(serde_json::to_string(&TrustTier::Verified).unwrap(), "\"verified\"");
        assert_eq!(serde_json::to_string(&TrustTier::Corroborated).unwrap(), "\"corroborated\"");
    }

    #[test]
    fn provider_serde_kebab() {
        assert_eq!(serde_json::to_string(&ProviderTier::LocalSubstrate).unwrap(), "\"local-substrate\"");
        assert_eq!(serde_json::to_string(&ProviderTier::OpenWeights).unwrap(), "\"open-weights\"");
    }

    #[test]
    fn classification_serde_roundtrip() {
        let c = LlmOutputTrustClassifier::classify(feat(ProviderTier::Vendor, GroundTruth::Skipped, 3)).unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: TrustClassification = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
