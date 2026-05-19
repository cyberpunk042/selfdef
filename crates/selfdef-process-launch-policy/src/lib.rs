//! `selfdef-process-launch-policy` — process spawn authority.
//!
//! Allow rules pair a binary id with allowed `argv` prefixes
//! (`git status -s` allowed, `git push --force` denied). Deny rules
//! match a binary id + optional argv-prefix and always win over
//! allow. `never_launch` is a hard set of binary ids that are never
//! permitted regardless of other rules.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One allow rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllowRule {
    /// Binary id (shell name or absolute path).
    pub bin: String,
    /// Allowed argv prefix (empty = any args).
    pub argv_prefix: Vec<String>,
}

/// One deny rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DenyRule {
    /// Binary id.
    pub bin: String,
    /// Denied argv prefix (empty = any args of this bin).
    pub argv_prefix: Vec<String>,
}

/// Decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum LaunchDecision {
    /// Allowed with matched allow rule index.
    Allow {
        /// allow rule.
        rule_index: usize,
    },
    /// Denied by deny rule.
    DenyByDeny {
        /// deny rule.
        rule_index: usize,
    },
    /// Denied by never_launch entry.
    DenyByNever {
        /// binary.
        bin: String,
    },
    /// Denied by no matching allow.
    DenyImplicit,
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessLaunchPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Allow rules.
    pub allow: Vec<AllowRule>,
    /// Deny rules.
    pub deny: Vec<DenyRule>,
    /// Never-launch binaries.
    pub never_launch: Vec<String>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ProcessLaunchError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty bin in rule.
    #[error("empty bin in {0}")]
    EmptyBin(String),
}

impl ProcessLaunchPolicy {
    /// New empty (deny-all).
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            allow: Vec::new(),
            deny: Vec::new(),
            never_launch: Vec::new(),
        }
    }

    /// Decide a (bin, argv).
    pub fn decide(&self, bin: &str, argv: &[&str]) -> LaunchDecision {
        if self.never_launch.iter().any(|n| n == bin) {
            return LaunchDecision::DenyByNever { bin: bin.into() };
        }
        for (i, d) in self.deny.iter().enumerate() {
            if d.bin == bin && argv_starts_with(argv, &d.argv_prefix) {
                return LaunchDecision::DenyByDeny { rule_index: i };
            }
        }
        for (i, a) in self.allow.iter().enumerate() {
            if a.bin == bin && argv_starts_with(argv, &a.argv_prefix) {
                return LaunchDecision::Allow { rule_index: i };
            }
        }
        LaunchDecision::DenyImplicit
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ProcessLaunchError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ProcessLaunchError::SchemaMismatch);
        }
        for r in &self.allow {
            if r.bin.is_empty() { return Err(ProcessLaunchError::EmptyBin("allow".into())); }
        }
        for r in &self.deny {
            if r.bin.is_empty() { return Err(ProcessLaunchError::EmptyBin("deny".into())); }
        }
        for n in &self.never_launch {
            if n.is_empty() { return Err(ProcessLaunchError::EmptyBin("never_launch".into())); }
        }
        Ok(())
    }
}

fn argv_starts_with(argv: &[&str], prefix: &[String]) -> bool {
    if prefix.len() > argv.len() { return false; }
    for (i, p) in prefix.iter().enumerate() {
        if argv[i] != p.as_str() { return false; }
    }
    true
}

impl Default for ProcessLaunchPolicy {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(bin: &str, args: &[&str]) -> AllowRule {
        AllowRule { bin: bin.into(), argv_prefix: args.iter().map(|s| (*s).into()).collect() }
    }

    fn deny(bin: &str, args: &[&str]) -> DenyRule {
        DenyRule { bin: bin.into(), argv_prefix: args.iter().map(|s| (*s).into()).collect() }
    }

    #[test]
    fn empty_policy_denies() {
        let p = ProcessLaunchPolicy::new();
        assert!(matches!(p.decide("ls", &[]), LaunchDecision::DenyImplicit));
    }

    #[test]
    fn allow_bin_no_prefix_grants_any_args() {
        let mut p = ProcessLaunchPolicy::new();
        p.allow.push(allow("ls", &[]));
        assert!(matches!(p.decide("ls", &["-la"]), LaunchDecision::Allow { .. }));
    }

    #[test]
    fn allow_with_prefix_matches_only_prefix() {
        let mut p = ProcessLaunchPolicy::new();
        p.allow.push(allow("git", &["status"]));
        assert!(matches!(p.decide("git", &["status", "-s"]), LaunchDecision::Allow { .. }));
        assert!(matches!(p.decide("git", &["push"]), LaunchDecision::DenyImplicit));
    }

    #[test]
    fn deny_overrides_allow() {
        let mut p = ProcessLaunchPolicy::new();
        p.allow.push(allow("git", &[]));
        p.deny.push(deny("git", &["push", "--force"]));
        assert!(matches!(p.decide("git", &["push", "--force"]), LaunchDecision::DenyByDeny { .. }));
        assert!(matches!(p.decide("git", &["status"]), LaunchDecision::Allow { .. }));
    }

    #[test]
    fn never_overrides_everything() {
        let mut p = ProcessLaunchPolicy::new();
        p.allow.push(allow("rm", &[]));
        p.never_launch.push("rm".into());
        let d = p.decide("rm", &["-rf", "/"]);
        match d {
            LaunchDecision::DenyByNever { bin } => assert_eq!(bin, "rm"),
            _ => panic!("expected DenyByNever"),
        }
    }

    #[test]
    fn empty_argv_matches_empty_prefix() {
        let mut p = ProcessLaunchPolicy::new();
        p.allow.push(allow("uname", &[]));
        assert!(matches!(p.decide("uname", &[]), LaunchDecision::Allow { .. }));
    }

    #[test]
    fn prefix_longer_than_argv_no_match() {
        let mut p = ProcessLaunchPolicy::new();
        p.allow.push(allow("git", &["status", "-s"]));
        assert!(matches!(p.decide("git", &["status"]), LaunchDecision::DenyImplicit));
    }

    #[test]
    fn empty_bin_rejected_on_validate() {
        let mut p = ProcessLaunchPolicy::new();
        p.allow.push(allow("", &[]));
        assert!(matches!(p.validate().unwrap_err(), ProcessLaunchError::EmptyBin(_)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = ProcessLaunchPolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), ProcessLaunchError::SchemaMismatch));
    }

    #[test]
    fn decision_serde_kebab() {
        let d = LaunchDecision::DenyByNever { bin: "rm".into() };
        let j = serde_json::to_string(&d).unwrap();
        assert!(j.contains("\"kind\":\"deny-by-never\""));
        let d = LaunchDecision::DenyImplicit;
        let j = serde_json::to_string(&d).unwrap();
        assert!(j.contains("\"kind\":\"deny-implicit\""));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let mut p = ProcessLaunchPolicy::new();
        p.allow.push(allow("git", &["status"]));
        p.deny.push(deny("git", &["push", "--force"]));
        p.never_launch.push("rm".into());
        let j = serde_json::to_string(&p).unwrap();
        let back: ProcessLaunchPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
