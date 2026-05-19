//! `selfdef-collector-quarantine-ledger` — append-only collector quarantine record.
//!
//! Each entry records: collector kind, reason it was quarantined, sampled EPS
//! at the time, ISO-8601 quarantined-at timestamp, and (when re-armed)
//! cleared-at timestamp. The daemon writes one entry every time a collector
//! transitions in or out of quarantine; the ledger is the authoritative
//! audit trail.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_collector_source_taxonomy::CollectorKind;
use selfdef_collector_budget_guard::BudgetVerdict;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Reason a collector got quarantined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QuarantineReason {
    /// EPS exceeded hard ceiling.
    HardEpsBreach,
    /// Collector emitted a schema-invalid event.
    SchemaInvalid,
    /// Collector handle died / process crashed.
    HandleDied,
    /// Operator explicitly quarantined via CLI.
    OperatorForced,
    /// Substrate self-test detected drift.
    SelfTestDrift,
}

/// One quarantine ledger entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuarantineEntry {
    /// Which collector.
    pub kind: CollectorKind,
    /// Reason.
    pub reason: QuarantineReason,
    /// Sampled EPS at quarantine time.
    pub eps_at_quarantine: u32,
    /// ISO-8601 UTC.
    pub quarantined_at: String,
    /// ISO-8601 UTC when re-armed; empty string while still quarantined.
    pub cleared_at: String,
}

/// Ledger envelope (append-only in practice; the type is a Vec for transport).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuarantineLedger {
    /// Schema version.
    pub schema_version: String,
    /// Entries in append order.
    pub entries: Vec<QuarantineEntry>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum LedgerError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// quarantined_at empty.
    #[error("entry {idx} missing quarantined_at")]
    MissingTimestamp {
        /// Index.
        idx: usize,
    },
    /// cleared_at < quarantined_at (string comparison; ISO-8601 sorts).
    #[error("entry {idx} cleared_at {cleared} precedes quarantined_at {at}")]
    ClearedBeforeQuarantined {
        /// Index.
        idx: usize,
        /// quarantined_at.
        at: String,
        /// cleared_at.
        cleared: String,
    },
}

impl QuarantineLedger {
    /// New empty ledger.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            entries: Vec::new(),
        }
    }

    /// Append a new quarantine event.
    pub fn open(&mut self, kind: CollectorKind, reason: QuarantineReason, eps: u32, at: &str) {
        self.entries.push(QuarantineEntry {
            kind,
            reason,
            eps_at_quarantine: eps,
            quarantined_at: at.into(),
            cleared_at: String::new(),
        });
    }

    /// Close the most-recent open entry for a collector.
    /// Returns true if an entry was closed.
    pub fn close(&mut self, kind: CollectorKind, at: &str) -> bool {
        for e in self.entries.iter_mut().rev() {
            if e.kind == kind && e.cleared_at.is_empty() {
                e.cleared_at = at.into();
                return true;
            }
        }
        false
    }

    /// True if the collector has an open entry.
    pub fn is_quarantined(&self, kind: CollectorKind) -> bool {
        self.entries.iter().any(|e| e.kind == kind && e.cleared_at.is_empty())
    }

    /// Count currently-quarantined collectors (distinct).
    pub fn open_count(&self) -> usize {
        use std::collections::HashSet;
        let mut s: HashSet<CollectorKind> = HashSet::new();
        for e in &self.entries {
            if e.cleared_at.is_empty() {
                s.insert(e.kind);
            }
        }
        s.len()
    }

    /// Validate the ledger structurally.
    pub fn validate(&self) -> Result<(), LedgerError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(LedgerError::SchemaMismatch);
        }
        for (idx, e) in self.entries.iter().enumerate() {
            if e.quarantined_at.is_empty() {
                return Err(LedgerError::MissingTimestamp { idx });
            }
            if !e.cleared_at.is_empty() && e.cleared_at < e.quarantined_at {
                return Err(LedgerError::ClearedBeforeQuarantined {
                    idx,
                    at: e.quarantined_at.clone(),
                    cleared: e.cleared_at.clone(),
                });
            }
        }
        Ok(())
    }
}

impl Default for QuarantineLedger {
    fn default() -> Self { Self::new() }
}

/// Translate a BudgetVerdict + sampled EPS into the corresponding ledger
/// action: Quarantine → open new entry; Warn / Within → no-op.
pub fn apply_verdict(
    ledger: &mut QuarantineLedger,
    kind: CollectorKind,
    verdict: BudgetVerdict,
    eps: u32,
    at: &str,
) -> bool {
    if verdict == BudgetVerdict::Quarantine && !ledger.is_quarantined(kind) {
        ledger.open(kind, QuarantineReason::HardEpsBreach, eps, at);
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_ledger_validates() {
        QuarantineLedger::new().validate().unwrap();
    }

    #[test]
    fn open_then_close_roundtrip() {
        let mut l = QuarantineLedger::new();
        l.open(CollectorKind::Auditd, QuarantineReason::HardEpsBreach, 25_000, "2026-05-19T03:00:00Z");
        assert!(l.is_quarantined(CollectorKind::Auditd));
        assert_eq!(l.open_count(), 1);
        assert!(l.close(CollectorKind::Auditd, "2026-05-19T03:05:00Z"));
        assert!(!l.is_quarantined(CollectorKind::Auditd));
        assert_eq!(l.open_count(), 0);
        l.validate().unwrap();
    }

    #[test]
    fn close_nonexistent_returns_false() {
        let mut l = QuarantineLedger::new();
        assert!(!l.close(CollectorKind::Auditd, "2026-05-19T03:05:00Z"));
    }

    #[test]
    fn open_count_distinct_per_collector() {
        let mut l = QuarantineLedger::new();
        l.open(CollectorKind::Auditd, QuarantineReason::HardEpsBreach, 25_000, "t1");
        l.open(CollectorKind::Suricata, QuarantineReason::SchemaInvalid, 9_000, "t2");
        assert_eq!(l.open_count(), 2);
        l.close(CollectorKind::Auditd, "t3");
        assert_eq!(l.open_count(), 1);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut l = QuarantineLedger::new();
        l.schema_version = "9.9.9".into();
        assert!(matches!(l.validate().unwrap_err(), LedgerError::SchemaMismatch));
    }

    #[test]
    fn missing_timestamp_caught() {
        let mut l = QuarantineLedger::new();
        l.entries.push(QuarantineEntry {
            kind: CollectorKind::Auditd,
            reason: QuarantineReason::OperatorForced,
            eps_at_quarantine: 0,
            quarantined_at: String::new(),
            cleared_at: String::new(),
        });
        assert!(matches!(l.validate().unwrap_err(), LedgerError::MissingTimestamp { idx: 0 }));
    }

    #[test]
    fn cleared_before_quarantined_caught() {
        let mut l = QuarantineLedger::new();
        l.entries.push(QuarantineEntry {
            kind: CollectorKind::Auditd,
            reason: QuarantineReason::HardEpsBreach,
            eps_at_quarantine: 25_000,
            quarantined_at: "2026-05-19T03:00:00Z".into(),
            cleared_at: "2026-05-19T02:00:00Z".into(),
        });
        match l.validate().unwrap_err() {
            LedgerError::ClearedBeforeQuarantined { idx, .. } => assert_eq!(idx, 0),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn apply_verdict_quarantines_on_hard() {
        let mut l = QuarantineLedger::new();
        let opened = apply_verdict(&mut l, CollectorKind::Ebpf, BudgetVerdict::Quarantine, 45_000, "t1");
        assert!(opened);
        assert!(l.is_quarantined(CollectorKind::Ebpf));
    }

    #[test]
    fn apply_verdict_noop_on_warn_or_within() {
        let mut l = QuarantineLedger::new();
        assert!(!apply_verdict(&mut l, CollectorKind::Ebpf, BudgetVerdict::Warn, 15_000, "t"));
        assert!(!apply_verdict(&mut l, CollectorKind::Ebpf, BudgetVerdict::Within, 100, "t"));
        assert!(l.entries.is_empty());
    }

    #[test]
    fn apply_verdict_idempotent_if_already_open() {
        let mut l = QuarantineLedger::new();
        apply_verdict(&mut l, CollectorKind::Ebpf, BudgetVerdict::Quarantine, 45_000, "t1");
        let second = apply_verdict(&mut l, CollectorKind::Ebpf, BudgetVerdict::Quarantine, 50_000, "t2");
        assert!(!second);
        assert_eq!(l.entries.len(), 1);
    }

    #[test]
    fn reason_serde_kebab() {
        assert_eq!(serde_json::to_string(&QuarantineReason::HardEpsBreach).unwrap(), "\"hard-eps-breach\"");
        assert_eq!(serde_json::to_string(&QuarantineReason::SchemaInvalid).unwrap(), "\"schema-invalid\"");
        assert_eq!(serde_json::to_string(&QuarantineReason::HandleDied).unwrap(), "\"handle-died\"");
        assert_eq!(serde_json::to_string(&QuarantineReason::OperatorForced).unwrap(), "\"operator-forced\"");
        assert_eq!(serde_json::to_string(&QuarantineReason::SelfTestDrift).unwrap(), "\"self-test-drift\"");
    }

    #[test]
    fn ledger_serde_roundtrip() {
        let mut l = QuarantineLedger::new();
        l.open(CollectorKind::Auditd, QuarantineReason::HardEpsBreach, 25_000, "t1");
        l.close(CollectorKind::Auditd, "t2");
        let j = serde_json::to_string(&l).unwrap();
        let back: QuarantineLedger = serde_json::from_str(&j).unwrap();
        assert_eq!(l, back);
    }
}
