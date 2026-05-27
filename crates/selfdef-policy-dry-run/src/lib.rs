//! `selfdef-policy-dry-run` — record-only mode for new policies.
//!
//! `set_mode(policy, Mode::Enforce|DryRun)`. `observe(policy,
//! would_deny, reason)` records what the policy WOULD have done.
//! In Enforce mode, callers honor the verdict; in DryRun, they
//! ignore it but the observations accumulate per policy for review.
//!
//! `report(policy)` returns counts of would-allow vs would-deny
//! and the top-K reasons.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Enforce.
    Enforce,
    /// Dry run (record only).
    DryRun,
}

/// Per-policy stats.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyStats {
    /// Mode.
    pub mode: Option<Mode>,
    /// Would-allow count.
    pub would_allow: u64,
    /// Would-deny count.
    pub would_deny: u64,
    /// reason → count.
    pub reasons: BTreeMap<String, u64>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDryRun {
    /// Schema version.
    pub schema_version: String,
    /// policy → stats.
    pub stats: BTreeMap<String, PolicyStats>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DryRunError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("policy id empty")]
    EmptyPolicy,
    /// Empty.
    #[error("reason empty")]
    EmptyReason,
}

impl PolicyDryRun {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            stats: BTreeMap::new(),
        }
    }

    /// Set mode.
    pub fn set_mode(&mut self, policy: &str, mode: Mode) -> Result<(), DryRunError> {
        if policy.is_empty() {
            return Err(DryRunError::EmptyPolicy);
        }
        self.stats.entry(policy.into()).or_default().mode = Some(mode);
        Ok(())
    }

    /// Mode of a policy (default = DryRun until set).
    pub fn mode_of(&self, policy: &str) -> Mode {
        self.stats
            .get(policy)
            .and_then(|s| s.mode)
            .unwrap_or(Mode::DryRun)
    }

    /// Observe a decision the policy would have produced.
    pub fn observe(
        &mut self,
        policy: &str,
        would_deny: bool,
        reason: &str,
    ) -> Result<(), DryRunError> {
        if policy.is_empty() {
            return Err(DryRunError::EmptyPolicy);
        }
        let s = self.stats.entry(policy.into()).or_default();
        if would_deny {
            if reason.is_empty() {
                return Err(DryRunError::EmptyReason);
            }
            s.would_deny = s.would_deny.saturating_add(1);
            *s.reasons.entry(reason.into()).or_insert(0) += 1;
        } else {
            s.would_allow = s.would_allow.saturating_add(1);
        }
        Ok(())
    }

    /// Top-K reasons by count.
    pub fn top_reasons(&self, policy: &str, n: usize) -> Vec<(String, u64)> {
        let Some(s) = self.stats.get(policy) else {
            return Vec::new();
        };
        let mut v: Vec<(String, u64)> = s.reasons.iter().map(|(k, c)| (k.clone(), *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }

    /// Counts.
    pub fn counts(&self, policy: &str) -> (u64, u64) {
        self.stats
            .get(policy)
            .map(|s| (s.would_allow, s.would_deny))
            .unwrap_or((0, 0))
    }

    /// Reset.
    pub fn reset(&mut self, policy: &str) -> bool {
        self.stats.remove(policy).is_some()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DryRunError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(DryRunError::SchemaMismatch);
        }
        for k in self.stats.keys() {
            if k.is_empty() {
                return Err(DryRunError::EmptyPolicy);
            }
        }
        Ok(())
    }
}

impl Default for PolicyDryRun {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mode_is_dry_run() {
        let d = PolicyDryRun::new();
        assert_eq!(d.mode_of("p"), Mode::DryRun);
    }

    #[test]
    fn set_mode_enforce() {
        let mut d = PolicyDryRun::new();
        d.set_mode("p", Mode::Enforce).unwrap();
        assert_eq!(d.mode_of("p"), Mode::Enforce);
    }

    #[test]
    fn observe_counts() {
        let mut d = PolicyDryRun::new();
        d.observe("p", false, "").unwrap();
        d.observe("p", true, "rate-limited").unwrap();
        d.observe("p", true, "rate-limited").unwrap();
        let (allow, deny) = d.counts("p");
        assert_eq!(allow, 1);
        assert_eq!(deny, 2);
    }

    #[test]
    fn top_reasons_sorted_desc() {
        let mut d = PolicyDryRun::new();
        d.observe("p", true, "a").unwrap();
        d.observe("p", true, "a").unwrap();
        d.observe("p", true, "b").unwrap();
        d.observe("p", true, "c").unwrap();
        d.observe("p", true, "c").unwrap();
        d.observe("p", true, "c").unwrap();
        let t = d.top_reasons("p", 2);
        assert_eq!(t[0], ("c".into(), 3));
        assert_eq!(t[1], ("a".into(), 2));
    }

    #[test]
    fn reset_clears() {
        let mut d = PolicyDryRun::new();
        d.observe("p", true, "x").unwrap();
        assert!(d.reset("p"));
        assert_eq!(d.counts("p"), (0, 0));
    }

    #[test]
    fn deny_requires_reason() {
        let mut d = PolicyDryRun::new();
        assert!(matches!(
            d.observe("p", true, "").unwrap_err(),
            DryRunError::EmptyReason
        ));
    }

    #[test]
    fn empty_policy_rejected() {
        let mut d = PolicyDryRun::new();
        assert!(matches!(
            d.observe("", false, "").unwrap_err(),
            DryRunError::EmptyPolicy
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut d = PolicyDryRun::new();
        d.schema_version = "9.9.9".into();
        assert!(matches!(
            d.validate().unwrap_err(),
            DryRunError::SchemaMismatch
        ));
    }

    #[test]
    fn dryrun_serde_roundtrip() {
        let mut d = PolicyDryRun::new();
        d.set_mode("p", Mode::Enforce).unwrap();
        d.observe("p", true, "x").unwrap();
        let j = serde_json::to_string(&d).unwrap();
        let back: PolicyDryRun = serde_json::from_str(&j).unwrap();
        assert_eq!(d, back);
    }
}
