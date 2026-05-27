//! `selfdef-substrate-syscall-allowlist` — per-substrate syscall control.
//!
//! Each substrate id has an allowlist of syscall names. `decide(
//! substrate_id, syscall)` returns:
//!   * `Allowed` — syscall is in the substrate's allowlist.
//!   * `Denied { reason }` — syscall absent or substrate has no list.
//!   * `Unknown` — substrate id not registered.
//!
//! `register(substrate_id)` creates an empty list. `allow(s, call)`,
//! `disallow(s, call)`. `count(s)` returns the number of denial
//! observations recorded via `observe_decision()`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-substrate config.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubstrateAllowlist {
    /// Allowed syscalls.
    pub allowed: BTreeSet<String>,
    /// Observed allow count (for telemetry).
    pub allow_count: u64,
    /// Observed deny count.
    pub deny_count: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyscallAllowlist {
    /// Schema version.
    pub schema_version: String,
    /// substrate_id → allowlist.
    pub substrates: BTreeMap<String, SubstrateAllowlist>,
}

/// Verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SyscallVerdict {
    /// Allowed.
    Allowed,
    /// Denied.
    Denied {
        /// reason.
        reason: String,
    },
    /// Unknown substrate.
    Unknown,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SyscallError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty substrate.
    #[error("substrate id empty")]
    EmptySubstrate,
    /// Empty syscall.
    #[error("syscall name empty")]
    EmptyCall,
    /// Unknown substrate.
    #[error("unknown substrate: {0}")]
    UnknownSubstrate(String),
}

impl SyscallAllowlist {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            substrates: BTreeMap::new(),
        }
    }

    /// Register an empty allowlist for a substrate.
    pub fn register(&mut self, substrate_id: &str) -> Result<(), SyscallError> {
        if substrate_id.is_empty() {
            return Err(SyscallError::EmptySubstrate);
        }
        self.substrates
            .entry(substrate_id.into())
            .or_insert_with(|| SubstrateAllowlist {
                allowed: BTreeSet::new(),
                allow_count: 0,
                deny_count: 0,
            });
        Ok(())
    }

    /// Allow a syscall.
    pub fn allow(&mut self, substrate_id: &str, syscall: &str) -> Result<bool, SyscallError> {
        if syscall.is_empty() {
            return Err(SyscallError::EmptyCall);
        }
        let s = self
            .substrates
            .get_mut(substrate_id)
            .ok_or_else(|| SyscallError::UnknownSubstrate(substrate_id.into()))?;
        Ok(s.allowed.insert(syscall.into()))
    }

    /// Disallow a syscall.
    pub fn disallow(&mut self, substrate_id: &str, syscall: &str) -> Result<bool, SyscallError> {
        let s = self
            .substrates
            .get_mut(substrate_id)
            .ok_or_else(|| SyscallError::UnknownSubstrate(substrate_id.into()))?;
        Ok(s.allowed.remove(syscall))
    }

    /// Pure decision — no telemetry side-effect.
    pub fn decide(&self, substrate_id: &str, syscall: &str) -> SyscallVerdict {
        match self.substrates.get(substrate_id) {
            None => SyscallVerdict::Unknown,
            Some(s) => {
                if s.allowed.contains(syscall) {
                    SyscallVerdict::Allowed
                } else {
                    SyscallVerdict::Denied {
                        reason: format!("syscall not on allowlist: {syscall}"),
                    }
                }
            }
        }
    }

    /// Observe a decision (increments telemetry counters).
    pub fn observe_decision(&mut self, substrate_id: &str, syscall: &str) -> SyscallVerdict {
        let verdict = self.decide(substrate_id, syscall);
        if let Some(s) = self.substrates.get_mut(substrate_id) {
            match &verdict {
                SyscallVerdict::Allowed => s.allow_count = s.allow_count.saturating_add(1),
                SyscallVerdict::Denied { .. } => s.deny_count = s.deny_count.saturating_add(1),
                SyscallVerdict::Unknown => {}
            }
        }
        verdict
    }

    /// Counts (allow, deny).
    pub fn counts(&self, substrate_id: &str) -> Option<(u64, u64)> {
        self.substrates
            .get(substrate_id)
            .map(|s| (s.allow_count, s.deny_count))
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), SyscallError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SyscallError::SchemaMismatch);
        }
        for (id, s) in &self.substrates {
            if id.is_empty() {
                return Err(SyscallError::EmptySubstrate);
            }
            for c in &s.allowed {
                if c.is_empty() {
                    return Err(SyscallError::EmptyCall);
                }
            }
        }
        Ok(())
    }
}

impl Default for SyscallAllowlist {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_after_allow() {
        let mut s = SyscallAllowlist::new();
        s.register("sandbox-a").unwrap();
        s.allow("sandbox-a", "read").unwrap();
        assert_eq!(s.decide("sandbox-a", "read"), SyscallVerdict::Allowed);
    }

    #[test]
    fn denied_when_not_listed() {
        let mut s = SyscallAllowlist::new();
        s.register("sandbox-a").unwrap();
        assert!(matches!(
            s.decide("sandbox-a", "exec"),
            SyscallVerdict::Denied { .. }
        ));
    }

    #[test]
    fn unknown_substrate() {
        let s = SyscallAllowlist::new();
        assert_eq!(s.decide("nope", "read"), SyscallVerdict::Unknown);
    }

    #[test]
    fn disallow_removes() {
        let mut s = SyscallAllowlist::new();
        s.register("sandbox-a").unwrap();
        s.allow("sandbox-a", "read").unwrap();
        assert!(s.disallow("sandbox-a", "read").unwrap());
        assert!(matches!(
            s.decide("sandbox-a", "read"),
            SyscallVerdict::Denied { .. }
        ));
    }

    #[test]
    fn observe_increments_counters() {
        let mut s = SyscallAllowlist::new();
        s.register("sandbox-a").unwrap();
        s.allow("sandbox-a", "read").unwrap();
        s.observe_decision("sandbox-a", "read");
        s.observe_decision("sandbox-a", "exec");
        let (a, d) = s.counts("sandbox-a").unwrap();
        assert_eq!(a, 1);
        assert_eq!(d, 1);
    }

    #[test]
    fn register_idempotent() {
        let mut s = SyscallAllowlist::new();
        s.register("a").unwrap();
        s.allow("a", "read").unwrap();
        s.register("a").unwrap();
        // Existing allowlist preserved.
        assert_eq!(s.decide("a", "read"), SyscallVerdict::Allowed);
    }

    #[test]
    fn empty_substrate_rejected() {
        let mut s = SyscallAllowlist::new();
        assert!(matches!(
            s.register("").unwrap_err(),
            SyscallError::EmptySubstrate
        ));
    }

    #[test]
    fn empty_syscall_rejected() {
        let mut s = SyscallAllowlist::new();
        s.register("a").unwrap();
        assert!(matches!(
            s.allow("a", "").unwrap_err(),
            SyscallError::EmptyCall
        ));
    }

    #[test]
    fn allow_unknown_substrate_rejected() {
        let mut s = SyscallAllowlist::new();
        assert!(matches!(
            s.allow("nope", "read").unwrap_err(),
            SyscallError::UnknownSubstrate(_)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = SyscallAllowlist::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            SyscallError::SchemaMismatch
        ));
    }

    #[test]
    fn syscall_serde_roundtrip() {
        let mut s = SyscallAllowlist::new();
        s.register("a").unwrap();
        s.allow("a", "read").unwrap();
        s.observe_decision("a", "read");
        let j = serde_json::to_string(&s).unwrap();
        let back: SyscallAllowlist = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
