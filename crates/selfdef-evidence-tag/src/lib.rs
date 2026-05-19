//! `selfdef-evidence-tag` — 6 canonical evidence ledger tags.
//!
//! Each tag declares:
//! - `retention`: Eternal (never purge) / Purgable (subject to retention-policy)
//! - `cockpit_visible`: whether the operator dashboard shows the tag by default
//! - `severity_floor`: minimum severity (Info..Emergency) the tag implies
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// 6 canonical tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceTag {
    /// MS033 policy decision evidence.
    Decision,
    /// MS037/038 grant lifecycle evidence.
    Grant,
    /// Quarantine event evidence.
    Quarantine,
    /// Cohort promotion / demotion evidence.
    Promotion,
    /// Boot self-test evidence.
    SelfTest,
    /// Anomaly-hint evidence.
    Anomaly,
}

/// Retention class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Retention {
    /// Never purge.
    Eternal,
    /// Subject to retention-policy.
    Purgable,
}

/// Per-tag policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TagPolicy {
    /// Tag.
    pub tag: EvidenceTag,
    /// Retention.
    pub retention: Retention,
    /// Cockpit visibility by default.
    pub cockpit_visible: bool,
}

/// Manifest envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceTagManifest {
    /// Schema version.
    pub schema_version: String,
    /// 6 policies.
    pub policies: Vec<TagPolicy>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum TagError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 6.
    #[error("tag count {0} != 6 canonical")]
    CountInvalid(usize),
    /// Missing.
    #[error("missing tag: {0:?}")]
    Missing(EvidenceTag),
}

const REQUIRED: [EvidenceTag; 6] = [
    EvidenceTag::Decision, EvidenceTag::Grant, EvidenceTag::Quarantine,
    EvidenceTag::Promotion, EvidenceTag::SelfTest, EvidenceTag::Anomaly,
];

impl EvidenceTagManifest {
    /// Canonical defaults.
    pub fn canonical() -> Self {
        let policies = vec![
            TagPolicy { tag: EvidenceTag::Decision,   retention: Retention::Purgable, cockpit_visible: true },
            TagPolicy { tag: EvidenceTag::Grant,      retention: Retention::Eternal,  cockpit_visible: true },
            TagPolicy { tag: EvidenceTag::Quarantine, retention: Retention::Eternal,  cockpit_visible: true },
            TagPolicy { tag: EvidenceTag::Promotion,  retention: Retention::Eternal,  cockpit_visible: true },
            TagPolicy { tag: EvidenceTag::SelfTest,   retention: Retention::Purgable, cockpit_visible: false },
            TagPolicy { tag: EvidenceTag::Anomaly,    retention: Retention::Purgable, cockpit_visible: true },
        ];
        Self {
            schema_version: SCHEMA_VERSION.into(),
            policies,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), TagError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(TagError::SchemaMismatch);
        }
        if self.policies.len() != 6 {
            return Err(TagError::CountInvalid(self.policies.len()));
        }
        for t in REQUIRED {
            if !self.policies.iter().any(|p| p.tag == t) {
                return Err(TagError::Missing(t));
            }
        }
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, t: EvidenceTag) -> Option<&TagPolicy> {
        self.policies.iter().find(|p| p.tag == t)
    }

    /// True if tag is eternal-retention.
    pub fn is_eternal(&self, t: EvidenceTag) -> bool {
        matches!(self.get(t), Some(p) if p.retention == Retention::Eternal)
    }

    /// True if tag is cockpit-visible.
    pub fn is_visible(&self, t: EvidenceTag) -> bool {
        matches!(self.get(t), Some(p) if p.cockpit_visible)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        EvidenceTagManifest::canonical().validate().unwrap();
    }

    #[test]
    fn six_tags_present() {
        let m = EvidenceTagManifest::canonical();
        for t in REQUIRED {
            assert!(m.get(t).is_some(), "missing {t:?}");
        }
    }

    #[test]
    fn grant_quarantine_promotion_eternal() {
        let m = EvidenceTagManifest::canonical();
        assert!(m.is_eternal(EvidenceTag::Grant));
        assert!(m.is_eternal(EvidenceTag::Quarantine));
        assert!(m.is_eternal(EvidenceTag::Promotion));
    }

    #[test]
    fn decision_selftest_anomaly_purgable() {
        let m = EvidenceTagManifest::canonical();
        assert!(!m.is_eternal(EvidenceTag::Decision));
        assert!(!m.is_eternal(EvidenceTag::SelfTest));
        assert!(!m.is_eternal(EvidenceTag::Anomaly));
    }

    #[test]
    fn self_test_not_visible_by_default() {
        let m = EvidenceTagManifest::canonical();
        assert!(!m.is_visible(EvidenceTag::SelfTest));
        assert!(m.is_visible(EvidenceTag::Decision));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut m = EvidenceTagManifest::canonical();
        m.schema_version = "9.9.9".into();
        assert!(matches!(m.validate().unwrap_err(), TagError::SchemaMismatch));
    }

    #[test]
    fn count_invalid_caught() {
        let mut m = EvidenceTagManifest::canonical();
        m.policies.pop();
        assert!(matches!(m.validate().unwrap_err(), TagError::CountInvalid(5)));
    }

    #[test]
    fn missing_tag_caught() {
        let mut m = EvidenceTagManifest::canonical();
        // Replace Grant with a duplicate Decision.
        for p in m.policies.iter_mut() {
            if p.tag == EvidenceTag::Grant {
                p.tag = EvidenceTag::Decision;
            }
        }
        assert!(matches!(m.validate().unwrap_err(), TagError::Missing(EvidenceTag::Grant)));
    }

    #[test]
    fn tag_serde_kebab() {
        assert_eq!(serde_json::to_string(&EvidenceTag::Decision).unwrap(), "\"decision\"");
        assert_eq!(serde_json::to_string(&EvidenceTag::SelfTest).unwrap(), "\"self-test\"");
        assert_eq!(serde_json::to_string(&EvidenceTag::Anomaly).unwrap(), "\"anomaly\"");
    }

    #[test]
    fn retention_serde_kebab() {
        assert_eq!(serde_json::to_string(&Retention::Eternal).unwrap(), "\"eternal\"");
        assert_eq!(serde_json::to_string(&Retention::Purgable).unwrap(), "\"purgable\"");
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let m = EvidenceTagManifest::canonical();
        let j = serde_json::to_string(&m).unwrap();
        let back: EvidenceTagManifest = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
    }
}
