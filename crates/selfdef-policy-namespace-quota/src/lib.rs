//! `selfdef-policy-namespace-quota` — per-namespace policy-count cap.
//!
//! `set_cap(ns, max_policies)` configures a per-namespace cap.
//! `plan_install(ns, current_count)` returns:
//!   * `Accepted{remaining}` — current < cap; install would fit.
//!   * `CapReached{cap}` — current ≥ cap; install rejected.
//!   * `UnknownNamespace` — no cap configured.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyNamespaceQuota {
    /// Schema version.
    pub schema_version: String,
    /// ns → cap.
    pub caps: BTreeMap<String, u32>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum InstallVerdict {
    /// Would install; remaining slots.
    Accepted {
        /// Slots remaining after install.
        remaining: u32,
    },
    /// Cap reached.
    CapReached {
        /// cap.
        cap: u32,
    },
    /// No quota configured.
    UnknownNamespace,
}

/// Errors.
#[derive(Debug, Error)]
pub enum QuotaError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty namespace.
    #[error("namespace empty")]
    EmptyNs,
}

impl PolicyNamespaceQuota {
    /// New.
    pub fn new() -> Self {
        Self { schema_version: SCHEMA_VERSION.into(), caps: BTreeMap::new() }
    }

    /// Set cap.
    pub fn set_cap(&mut self, ns: &str, max_policies: u32) -> Result<(), QuotaError> {
        if ns.is_empty() { return Err(QuotaError::EmptyNs); }
        self.caps.insert(ns.into(), max_policies);
        Ok(())
    }

    /// Plan an install.
    pub fn plan_install(&self, ns: &str, current_count: u32) -> InstallVerdict {
        let cap = match self.caps.get(ns) {
            Some(&c) => c,
            None => return InstallVerdict::UnknownNamespace,
        };
        if current_count >= cap {
            InstallVerdict::CapReached { cap }
        } else {
            InstallVerdict::Accepted { remaining: cap - current_count - 1 }
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), QuotaError> {
        if self.schema_version != SCHEMA_VERSION { return Err(QuotaError::SchemaMismatch); }
        for k in self.caps.keys() {
            if k.is_empty() { return Err(QuotaError::EmptyNs); }
        }
        Ok(())
    }
}

impl Default for PolicyNamespaceQuota {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_under_cap() {
        let mut q = PolicyNamespaceQuota::new();
        q.set_cap("ns/a", 10).unwrap();
        let v = q.plan_install("ns/a", 3);
        assert_eq!(v, InstallVerdict::Accepted { remaining: 6 });
    }

    #[test]
    fn cap_reached_when_at_cap() {
        let mut q = PolicyNamespaceQuota::new();
        q.set_cap("ns/a", 10).unwrap();
        assert_eq!(q.plan_install("ns/a", 10), InstallVerdict::CapReached { cap: 10 });
    }

    #[test]
    fn cap_reached_when_over_cap() {
        let mut q = PolicyNamespaceQuota::new();
        q.set_cap("ns/a", 10).unwrap();
        assert_eq!(q.plan_install("ns/a", 15), InstallVerdict::CapReached { cap: 10 });
    }

    #[test]
    fn unknown_namespace() {
        let q = PolicyNamespaceQuota::new();
        assert_eq!(q.plan_install("nope", 0), InstallVerdict::UnknownNamespace);
    }

    #[test]
    fn empty_ns_rejected() {
        let mut q = PolicyNamespaceQuota::new();
        assert!(matches!(q.set_cap("", 1).unwrap_err(), QuotaError::EmptyNs));
    }

    #[test]
    fn cap_zero_always_rejects() {
        let mut q = PolicyNamespaceQuota::new();
        q.set_cap("ns/x", 0).unwrap();
        assert_eq!(q.plan_install("ns/x", 0), InstallVerdict::CapReached { cap: 0 });
    }

    #[test]
    fn schema_drift_rejected() {
        let mut q = PolicyNamespaceQuota::new();
        q.schema_version = "9.9.9".into();
        assert!(matches!(q.validate().unwrap_err(), QuotaError::SchemaMismatch));
    }

    #[test]
    fn quota_serde_roundtrip() {
        let mut q = PolicyNamespaceQuota::new();
        q.set_cap("ns/a", 10).unwrap();
        let j = serde_json::to_string(&q).unwrap();
        let back: PolicyNamespaceQuota = serde_json::from_str(&j).unwrap();
        assert_eq!(q, back);
    }
}
