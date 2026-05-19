//! `selfdef-task-deadline-extension-policy` — deadline-creep gate.
//!
//! Per-TaskClass caps on (extension count, total extension seconds).
//! extend(class, current_extensions, current_total, requested) returns
//! Allow{new_total} / Denied{reason}. Prevents perpetual deadline
//! creep on operator-pinned long tasks.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Task class (mirror).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaskClass {
    /// Maintenance.
    Maintenance,
    /// Background.
    Background,
    /// Operator.
    Operator,
    /// Emergency.
    Emergency,
}

/// Per-class config.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClassExtension {
    /// Max distinct extensions per task.
    pub max_extensions: u32,
    /// Max total extension seconds per task.
    pub max_total_extension_seconds: u64,
}

/// Decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ExtendDecision {
    /// Granted; carries new_total.
    Allow {
        /// new total extension seconds.
        new_total: u64,
    },
    /// Hit count cap.
    DeniedCountCap {
        /// observed.
        observed: u32,
        /// cap.
        cap: u32,
    },
    /// Hit seconds cap.
    DeniedSecondsCap {
        /// requested total.
        requested_total: u64,
        /// cap.
        cap: u64,
    },
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskDeadlineExtensionPolicy {
    /// Schema version.
    pub schema_version: String,
    /// maintenance.
    pub maintenance: ClassExtension,
    /// background.
    pub background: ClassExtension,
    /// operator.
    pub operator: ClassExtension,
    /// emergency.
    pub emergency: ClassExtension,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ExtensionError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

impl TaskDeadlineExtensionPolicy {
    /// Canonical:
    /// * Maintenance: 0 (no extensions allowed).
    /// * Background: 3 extensions, 1h total.
    /// * Operator: 8, 24h.
    /// * Emergency: 16, 72h.
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            maintenance: ClassExtension { max_extensions: 0, max_total_extension_seconds: 0 },
            background: ClassExtension { max_extensions: 3, max_total_extension_seconds: 3600 },
            operator: ClassExtension { max_extensions: 8, max_total_extension_seconds: 24 * 3600 },
            emergency: ClassExtension { max_extensions: 16, max_total_extension_seconds: 72 * 3600 },
        }
    }

    /// Class config.
    pub fn class(&self, c: TaskClass) -> ClassExtension {
        match c {
            TaskClass::Maintenance => self.maintenance,
            TaskClass::Background => self.background,
            TaskClass::Operator => self.operator,
            TaskClass::Emergency => self.emergency,
        }
    }

    /// Extend.
    pub fn extend(
        &self,
        class: TaskClass,
        current_extensions: u32,
        current_total_seconds: u64,
        requested_seconds: u64,
    ) -> ExtendDecision {
        let cfg = self.class(class);
        let next_count = current_extensions + 1;
        if next_count > cfg.max_extensions {
            return ExtendDecision::DeniedCountCap {
                observed: next_count,
                cap: cfg.max_extensions,
            };
        }
        let new_total = current_total_seconds + requested_seconds;
        if new_total > cfg.max_total_extension_seconds {
            return ExtendDecision::DeniedSecondsCap {
                requested_total: new_total,
                cap: cfg.max_total_extension_seconds,
            };
        }
        ExtendDecision::Allow { new_total }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ExtensionError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ExtensionError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        TaskDeadlineExtensionPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn maintenance_never_extends() {
        let p = TaskDeadlineExtensionPolicy::canonical();
        assert!(matches!(
            p.extend(TaskClass::Maintenance, 0, 0, 10),
            ExtendDecision::DeniedCountCap { .. }
        ));
    }

    #[test]
    fn background_extends_within_cap() {
        let p = TaskDeadlineExtensionPolicy::canonical();
        assert!(matches!(
            p.extend(TaskClass::Background, 0, 0, 600),
            ExtendDecision::Allow { new_total: 600 }
        ));
    }

    #[test]
    fn background_seconds_cap_hit() {
        let p = TaskDeadlineExtensionPolicy::canonical();
        // background = 1h max. 3000+800 = 3800 > 3600.
        assert!(matches!(
            p.extend(TaskClass::Background, 0, 3000, 800),
            ExtendDecision::DeniedSecondsCap { .. }
        ));
    }

    #[test]
    fn background_count_cap_hit() {
        let p = TaskDeadlineExtensionPolicy::canonical();
        // current=3, next=4 > 3 cap.
        assert!(matches!(
            p.extend(TaskClass::Background, 3, 0, 60),
            ExtendDecision::DeniedCountCap { .. }
        ));
    }

    #[test]
    fn emergency_largest_caps() {
        let p = TaskDeadlineExtensionPolicy::canonical();
        assert!(matches!(
            p.extend(TaskClass::Emergency, 5, 60_000, 60_000),
            ExtendDecision::Allow { .. }
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = TaskDeadlineExtensionPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), ExtensionError::SchemaMismatch));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(serde_json::to_string(&TaskClass::Emergency).unwrap(), "\"emergency\"");
    }

    #[test]
    fn decision_serde_kebab() {
        let d = ExtendDecision::Allow { new_total: 0 };
        assert!(serde_json::to_string(&d).unwrap().contains("\"kind\":\"allow\""));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = TaskDeadlineExtensionPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: TaskDeadlineExtensionPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
