//! `selfdef-audit-rotation-policy` — audit log segment rotation policy.
//!
//! Each audit class declares a rotation trigger + compression + retention.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Audit class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditClass {
    /// MS016 hash-chained audit.
    Audit,
    /// MS033 decisions.
    Decision,
    /// M049 trace spans.
    Span,
    /// Quarantine ledger.
    Quarantine,
    /// Evidence ledger.
    Evidence,
    /// Trust-score changes.
    TrustScore,
    /// Boundary-flip log.
    Boundary,
}

/// Rotation trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "value")]
pub enum RotationTrigger {
    /// Daily rotation.
    Daily,
    /// Weekly rotation.
    Weekly,
    /// Monthly rotation.
    Monthly,
    /// By-size (rotate after N bytes written).
    BySize(u64),
    /// On a specific event (e.g. operator-triggered).
    OnEvent,
}

/// Compression preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Compression {
    /// No compression.
    None,
    /// gzip.
    Gzip,
    /// zstd.
    Zstd,
}

/// Per-class rotation policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RotationRule {
    /// Class.
    pub class: AuditClass,
    /// Trigger.
    pub trigger: RotationTrigger,
    /// Compression.
    pub compression: Compression,
    /// Minimum retention days (rotated segments retained ≥ this).
    pub retention_days: u32,
}

/// Policy envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRotationPolicy {
    /// Schema version.
    pub schema_version: String,
    /// 7 rules.
    pub rules: Vec<RotationRule>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum AuditRotationError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 7.
    #[error("rule count {0} != 7 canonical")]
    CountInvalid(usize),
    /// Missing.
    #[error("missing class: {0:?}")]
    Missing(AuditClass),
    /// Zero retention.
    #[error("zero retention_days for {0:?}")]
    ZeroRetention(AuditClass),
    /// Zero by-size threshold.
    #[error("zero BySize threshold for {0:?}")]
    ZeroBySize(AuditClass),
}

const REQUIRED: [AuditClass; 7] = [
    AuditClass::Audit,
    AuditClass::Decision,
    AuditClass::Span,
    AuditClass::Quarantine,
    AuditClass::Evidence,
    AuditClass::TrustScore,
    AuditClass::Boundary,
];

impl AuditRotationPolicy {
    /// Canonical defaults.
    pub fn canonical() -> Self {
        let rules = vec![
            RotationRule {
                class: AuditClass::Audit,
                trigger: RotationTrigger::Daily,
                compression: Compression::Zstd,
                retention_days: 3650,
            },
            RotationRule {
                class: AuditClass::Decision,
                trigger: RotationTrigger::Daily,
                compression: Compression::Zstd,
                retention_days: 365,
            },
            RotationRule {
                class: AuditClass::Span,
                trigger: RotationTrigger::BySize(100 * 1024 * 1024),
                compression: Compression::Zstd,
                retention_days: 90,
            },
            RotationRule {
                class: AuditClass::Quarantine,
                trigger: RotationTrigger::Weekly,
                compression: Compression::Gzip,
                retention_days: 1825,
            },
            RotationRule {
                class: AuditClass::Evidence,
                trigger: RotationTrigger::Daily,
                compression: Compression::Zstd,
                retention_days: 3650,
            },
            RotationRule {
                class: AuditClass::TrustScore,
                trigger: RotationTrigger::Weekly,
                compression: Compression::Gzip,
                retention_days: 365,
            },
            RotationRule {
                class: AuditClass::Boundary,
                trigger: RotationTrigger::OnEvent,
                compression: Compression::None,
                retention_days: 1825,
            },
        ];
        Self {
            schema_version: SCHEMA_VERSION.into(),
            rules,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), AuditRotationError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(AuditRotationError::SchemaMismatch);
        }
        if self.rules.len() != 7 {
            return Err(AuditRotationError::CountInvalid(self.rules.len()));
        }
        for c in REQUIRED {
            if !self.rules.iter().any(|r| r.class == c) {
                return Err(AuditRotationError::Missing(c));
            }
        }
        for r in &self.rules {
            if r.retention_days == 0 {
                return Err(AuditRotationError::ZeroRetention(r.class));
            }
            if let RotationTrigger::BySize(0) = r.trigger {
                return Err(AuditRotationError::ZeroBySize(r.class));
            }
        }
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, c: AuditClass) -> Option<&RotationRule> {
        self.rules.iter().find(|r| r.class == c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        AuditRotationPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn seven_classes_present() {
        let p = AuditRotationPolicy::canonical();
        for c in REQUIRED {
            assert!(p.get(c).is_some(), "missing {c:?}");
        }
    }

    #[test]
    fn audit_class_long_retention() {
        let p = AuditRotationPolicy::canonical();
        let r = p.get(AuditClass::Audit).unwrap();
        assert_eq!(r.retention_days, 3650);
        assert_eq!(r.compression, Compression::Zstd);
    }

    #[test]
    fn span_by_size_rotation() {
        let p = AuditRotationPolicy::canonical();
        let r = p.get(AuditClass::Span).unwrap();
        match r.trigger {
            RotationTrigger::BySize(n) => assert_eq!(n, 100 * 1024 * 1024),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn boundary_on_event_no_compression() {
        let p = AuditRotationPolicy::canonical();
        let r = p.get(AuditClass::Boundary).unwrap();
        assert_eq!(r.trigger, RotationTrigger::OnEvent);
        assert_eq!(r.compression, Compression::None);
    }

    #[test]
    fn zero_retention_rejected() {
        let mut p = AuditRotationPolicy::canonical();
        p.rules[0].retention_days = 0;
        assert!(matches!(
            p.validate().unwrap_err(),
            AuditRotationError::ZeroRetention(_)
        ));
    }

    #[test]
    fn zero_by_size_rejected() {
        let mut p = AuditRotationPolicy::canonical();
        for r in p.rules.iter_mut() {
            if r.class == AuditClass::Span {
                r.trigger = RotationTrigger::BySize(0);
            }
        }
        assert!(matches!(
            p.validate().unwrap_err(),
            AuditRotationError::ZeroBySize(_)
        ));
    }

    #[test]
    fn count_invalid_caught() {
        let mut p = AuditRotationPolicy::canonical();
        p.rules.pop();
        assert!(matches!(
            p.validate().unwrap_err(),
            AuditRotationError::CountInvalid(6)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = AuditRotationPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            AuditRotationError::SchemaMismatch
        ));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&AuditClass::Audit).unwrap(),
            "\"audit\""
        );
        assert_eq!(
            serde_json::to_string(&AuditClass::TrustScore).unwrap(),
            "\"trust-score\""
        );
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = AuditRotationPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: AuditRotationPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
