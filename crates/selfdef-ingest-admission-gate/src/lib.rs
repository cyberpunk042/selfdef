//! `selfdef-ingest-admission-gate` — ingest-time admission checks.
//!
//! Each inbound event is described by `Inbound { origin, kind, size_bytes }`.
//! The gate runs three sequential checks:
//!   1. `origin` must be on the allowlist (empty allowlist = deny).
//!   2. `kind` must not be on the deny-list.
//!   3. `size_bytes` must be ≤ `max_size_bytes`.
//!
//! `decide(event)` returns `Admitted` or the first failing
//! `Rejected { reason }`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Inbound event descriptor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Inbound {
    /// Origin label (e.g. "collector-x", "tool-y").
    pub origin: String,
    /// Event kind (e.g. "decision", "audit", "tool-call").
    pub kind: String,
    /// Payload size.
    pub size_bytes: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IngestAdmissionGate {
    /// Schema version.
    pub schema_version: String,
    /// Allowed origins (empty = deny all).
    pub origin_allowlist: BTreeSet<String>,
    /// Denied kinds.
    pub kind_denylist: BTreeSet<String>,
    /// Max size in bytes.
    pub max_size_bytes: u64,
    /// Total admitted.
    pub admitted_count: u64,
    /// Total rejected.
    pub rejected_count: u64,
}

/// Reason an event was rejected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "reason", rename_all = "kebab-case")]
pub enum RejectReason {
    /// Origin off allowlist.
    OriginNotAllowed {
        /// origin.
        origin: String,
    },
    /// Kind on denylist.
    KindDenied {
        /// kind.
        kind: String,
    },
    /// Too big.
    OverSize {
        /// actual.
        size_bytes: u64,
        /// limit.
        limit: u64,
    },
}

/// Verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AdmissionVerdict {
    /// Admitted.
    Admitted,
    /// Rejected.
    Rejected {
        /// reason.
        reason: RejectReason,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum GateError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty origin.
    #[error("origin empty")]
    EmptyOrigin,
    /// Empty kind.
    #[error("kind empty")]
    EmptyKind,
}

impl IngestAdmissionGate {
    /// New.
    pub fn new(max_size_bytes: u64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            origin_allowlist: BTreeSet::new(),
            kind_denylist: BTreeSet::new(),
            max_size_bytes,
            admitted_count: 0,
            rejected_count: 0,
        }
    }

    /// Allow an origin.
    pub fn allow_origin(&mut self, origin: &str) -> Result<bool, GateError> {
        if origin.is_empty() { return Err(GateError::EmptyOrigin); }
        Ok(self.origin_allowlist.insert(origin.into()))
    }

    /// Disallow an origin.
    pub fn disallow_origin(&mut self, origin: &str) -> bool {
        self.origin_allowlist.remove(origin)
    }

    /// Deny a kind.
    pub fn deny_kind(&mut self, kind: &str) -> Result<bool, GateError> {
        if kind.is_empty() { return Err(GateError::EmptyKind); }
        Ok(self.kind_denylist.insert(kind.into()))
    }

    /// Pure decision (no telemetry side-effect).
    pub fn decide(&self, ev: &Inbound) -> AdmissionVerdict {
        if !self.origin_allowlist.contains(&ev.origin) {
            return AdmissionVerdict::Rejected { reason: RejectReason::OriginNotAllowed { origin: ev.origin.clone() } };
        }
        if self.kind_denylist.contains(&ev.kind) {
            return AdmissionVerdict::Rejected { reason: RejectReason::KindDenied { kind: ev.kind.clone() } };
        }
        if ev.size_bytes > self.max_size_bytes {
            return AdmissionVerdict::Rejected { reason: RejectReason::OverSize { size_bytes: ev.size_bytes, limit: self.max_size_bytes } };
        }
        AdmissionVerdict::Admitted
    }

    /// Decide + record telemetry counters.
    pub fn observe(&mut self, ev: &Inbound) -> AdmissionVerdict {
        let v = self.decide(ev);
        match v {
            AdmissionVerdict::Admitted => self.admitted_count = self.admitted_count.saturating_add(1),
            AdmissionVerdict::Rejected { .. } => self.rejected_count = self.rejected_count.saturating_add(1),
        }
        v
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), GateError> {
        if self.schema_version != SCHEMA_VERSION { return Err(GateError::SchemaMismatch); }
        for o in &self.origin_allowlist {
            if o.is_empty() { return Err(GateError::EmptyOrigin); }
        }
        for k in &self.kind_denylist {
            if k.is_empty() { return Err(GateError::EmptyKind); }
        }
        Ok(())
    }
}

impl Default for IngestAdmissionGate {
    fn default() -> Self { Self::new(1024 * 1024) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(origin: &str, kind: &str, size: u64) -> Inbound {
        Inbound { origin: origin.into(), kind: kind.into(), size_bytes: size }
    }

    #[test]
    fn admit_when_all_pass() {
        let mut g = IngestAdmissionGate::new(1000);
        g.allow_origin("trusted").unwrap();
        assert_eq!(g.decide(&ev("trusted", "audit", 500)), AdmissionVerdict::Admitted);
    }

    #[test]
    fn reject_unknown_origin() {
        let g = IngestAdmissionGate::new(1000);
        match g.decide(&ev("rogue", "audit", 1)) {
            AdmissionVerdict::Rejected { reason: RejectReason::OriginNotAllowed { origin } } => {
                assert_eq!(origin, "rogue");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn reject_denied_kind() {
        let mut g = IngestAdmissionGate::new(1000);
        g.allow_origin("trusted").unwrap();
        g.deny_kind("toxic").unwrap();
        match g.decide(&ev("trusted", "toxic", 1)) {
            AdmissionVerdict::Rejected { reason: RejectReason::KindDenied { kind } } => {
                assert_eq!(kind, "toxic");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn reject_over_size() {
        let mut g = IngestAdmissionGate::new(100);
        g.allow_origin("trusted").unwrap();
        match g.decide(&ev("trusted", "audit", 200)) {
            AdmissionVerdict::Rejected { reason: RejectReason::OverSize { size_bytes, limit } } => {
                assert_eq!(size_bytes, 200);
                assert_eq!(limit, 100);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn check_order_origin_first() {
        let g = IngestAdmissionGate::new(100);
        // Origin denied, kind on denylist, size over — should report origin (first check).
        match g.decide(&ev("rogue", "toxic", 200)) {
            AdmissionVerdict::Rejected { reason: RejectReason::OriginNotAllowed { .. } } => {}
            _ => panic!(),
        }
    }

    #[test]
    fn observe_counts() {
        let mut g = IngestAdmissionGate::new(100);
        g.allow_origin("trusted").unwrap();
        g.observe(&ev("trusted", "audit", 50));
        g.observe(&ev("rogue", "audit", 50));
        assert_eq!(g.admitted_count, 1);
        assert_eq!(g.rejected_count, 1);
    }

    #[test]
    fn disallow_removes() {
        let mut g = IngestAdmissionGate::new(100);
        g.allow_origin("trusted").unwrap();
        assert!(g.disallow_origin("trusted"));
        assert!(matches!(g.decide(&ev("trusted", "audit", 1)), AdmissionVerdict::Rejected { .. }));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut g = IngestAdmissionGate::new(100);
        assert!(matches!(g.allow_origin("").unwrap_err(), GateError::EmptyOrigin));
        assert!(matches!(g.deny_kind("").unwrap_err(), GateError::EmptyKind));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut g = IngestAdmissionGate::new(100);
        g.schema_version = "9.9.9".into();
        assert!(matches!(g.validate().unwrap_err(), GateError::SchemaMismatch));
    }

    #[test]
    fn gate_serde_roundtrip() {
        let mut g = IngestAdmissionGate::new(100);
        g.allow_origin("trusted").unwrap();
        g.deny_kind("toxic").unwrap();
        let j = serde_json::to_string(&g).unwrap();
        let back: IngestAdmissionGate = serde_json::from_str(&j).unwrap();
        assert_eq!(g, back);
    }
}
