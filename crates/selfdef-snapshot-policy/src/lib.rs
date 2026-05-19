//! `selfdef-snapshot-policy` — IPS-side ZFS snapshot retention policy.
//!
//! Each of 7 canonical triggers declares (retain_count, age_days).
//! The daemon prunes a snapshot only when it falls outside the
//! intersection of all matching triggers' retention windows.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// 7 canonical snapshot triggers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotTrigger {
    /// Before commit (MS041).
    PreCommit,
    /// Before entering Execute mode.
    PreExecuteMode,
    /// Before applying a rule-pack update.
    PreRulePackUpdate,
    /// Before doctrine text mutation.
    PreDoctrineChange,
    /// Operator pushed the snapshot button.
    OperatorRequested,
    /// Periodic (cron-like).
    Periodic,
    /// Before promotion to Sandbox Tier 4.
    PreSandboxTier4,
}

/// Retention rule for one trigger.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetentionRule {
    /// Trigger.
    pub trigger: SnapshotTrigger,
    /// Number to retain (most-recent N).
    pub retain_count: u32,
    /// Max age in days; older than this is purgable even if within retain_count.
    pub age_days: u32,
}

/// Policy envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotPolicy {
    /// Schema version.
    pub schema_version: String,
    /// 7 rules.
    pub rules: Vec<RetentionRule>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SnapshotPolicyError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 7.
    #[error("rule count {0} != 7 canonical")]
    CountInvalid(usize),
    /// Missing trigger.
    #[error("missing trigger: {0:?}")]
    Missing(SnapshotTrigger),
    /// Zero-value rule.
    #[error("trigger {trigger:?} has zero retain_count or zero age_days")]
    ZeroValued {
        /// trigger.
        trigger: SnapshotTrigger,
    },
}

const REQUIRED: [SnapshotTrigger; 7] = [
    SnapshotTrigger::PreCommit, SnapshotTrigger::PreExecuteMode,
    SnapshotTrigger::PreRulePackUpdate, SnapshotTrigger::PreDoctrineChange,
    SnapshotTrigger::OperatorRequested, SnapshotTrigger::Periodic,
    SnapshotTrigger::PreSandboxTier4,
];

impl SnapshotPolicy {
    /// Canonical defaults.
    pub fn canonical() -> Self {
        let rules = vec![
            RetentionRule { trigger: SnapshotTrigger::PreCommit,           retain_count: 50,  age_days: 30  },
            RetentionRule { trigger: SnapshotTrigger::PreExecuteMode,      retain_count: 20,  age_days: 14  },
            RetentionRule { trigger: SnapshotTrigger::PreRulePackUpdate,   retain_count: 10,  age_days: 365 },
            RetentionRule { trigger: SnapshotTrigger::PreDoctrineChange,   retain_count: 10,  age_days: 365 },
            RetentionRule { trigger: SnapshotTrigger::OperatorRequested,   retain_count: 100, age_days: 90  },
            RetentionRule { trigger: SnapshotTrigger::Periodic,            retain_count: 24,  age_days: 7   },
            RetentionRule { trigger: SnapshotTrigger::PreSandboxTier4,     retain_count: 5,   age_days: 90  },
        ];
        Self {
            schema_version: SCHEMA_VERSION.into(),
            rules,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), SnapshotPolicyError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SnapshotPolicyError::SchemaMismatch);
        }
        if self.rules.len() != 7 {
            return Err(SnapshotPolicyError::CountInvalid(self.rules.len()));
        }
        for t in REQUIRED {
            if !self.rules.iter().any(|r| r.trigger == t) {
                return Err(SnapshotPolicyError::Missing(t));
            }
        }
        for r in &self.rules {
            if r.retain_count == 0 || r.age_days == 0 {
                return Err(SnapshotPolicyError::ZeroValued { trigger: r.trigger });
            }
        }
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, t: SnapshotTrigger) -> Option<&RetentionRule> {
        self.rules.iter().find(|r| r.trigger == t)
    }

    /// Should a snapshot of `trigger` taken `age_days_ago` days ago, with
    /// `position_in_recent_N` among same-trigger snapshots (0 = most recent),
    /// be retained?
    pub fn retain(&self, trigger: SnapshotTrigger, age_days_ago: u32, position: u32) -> bool {
        let Some(rule) = self.get(trigger) else { return false; };
        position < rule.retain_count && age_days_ago < rule.age_days
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        SnapshotPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn seven_triggers_present() {
        let p = SnapshotPolicy::canonical();
        for t in REQUIRED { assert!(p.get(t).is_some(), "missing {t:?}"); }
    }

    #[test]
    fn pre_commit_retains_50_within_30_days() {
        let p = SnapshotPolicy::canonical();
        // Position 0, 5 days ago → retain.
        assert!(p.retain(SnapshotTrigger::PreCommit, 5, 0));
        // Position 60 (over retain_count) → drop.
        assert!(!p.retain(SnapshotTrigger::PreCommit, 5, 60));
        // 100 days ago (over age) → drop.
        assert!(!p.retain(SnapshotTrigger::PreCommit, 100, 0));
    }

    #[test]
    fn periodic_has_short_age() {
        let p = SnapshotPolicy::canonical();
        assert_eq!(p.get(SnapshotTrigger::Periodic).unwrap().age_days, 7);
    }

    #[test]
    fn rule_pack_update_long_age() {
        let p = SnapshotPolicy::canonical();
        assert_eq!(p.get(SnapshotTrigger::PreRulePackUpdate).unwrap().age_days, 365);
    }

    #[test]
    fn doctrine_change_long_age() {
        let p = SnapshotPolicy::canonical();
        assert_eq!(p.get(SnapshotTrigger::PreDoctrineChange).unwrap().age_days, 365);
    }

    #[test]
    fn zero_valued_rejected() {
        let mut p = SnapshotPolicy::canonical();
        p.rules[0].retain_count = 0;
        assert!(matches!(p.validate().unwrap_err(), SnapshotPolicyError::ZeroValued { .. }));
    }

    #[test]
    fn count_invalid_caught() {
        let mut p = SnapshotPolicy::canonical();
        p.rules.pop();
        assert!(matches!(p.validate().unwrap_err(), SnapshotPolicyError::CountInvalid(6)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = SnapshotPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), SnapshotPolicyError::SchemaMismatch));
    }

    #[test]
    fn trigger_serde_kebab() {
        assert_eq!(serde_json::to_string(&SnapshotTrigger::PreCommit).unwrap(), "\"pre-commit\"");
        assert_eq!(serde_json::to_string(&SnapshotTrigger::PreExecuteMode).unwrap(), "\"pre-execute-mode\"");
        assert_eq!(serde_json::to_string(&SnapshotTrigger::OperatorRequested).unwrap(), "\"operator-requested\"");
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = SnapshotPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: SnapshotPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
