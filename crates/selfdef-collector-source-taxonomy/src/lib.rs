//! `selfdef-collector-source-taxonomy` — IPS-side 7-collector enumeration.
//!
//! Mirrors the actual `crates/selfdef-collector-*/` directory contents on disk.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// 7 IPS collector kinds (matches existing crates/selfdef-collector-*).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CollectorKind {
    /// auditd — Linux audit subsystem.
    Auditd,
    /// canary — synthetic event injector for tests.
    Canary,
    /// ebpf — eBPF probe collector.
    Ebpf,
    /// eventstream — JSONL file tailer.
    EventStream,
    /// journald — systemd journal.
    Journald,
    /// suricata — IDS eve.json.
    Suricata,
    /// tetragon — Tetragon kprobe/tracepoint events.
    Tetragon,
}

impl CollectorKind {
    /// Canonical 1..7 position.
    pub fn position(self) -> u8 {
        match self {
            CollectorKind::Auditd => 1,
            CollectorKind::Canary => 2,
            CollectorKind::Ebpf => 3,
            CollectorKind::EventStream => 4,
            CollectorKind::Journald => 5,
            CollectorKind::Suricata => 6,
            CollectorKind::Tetragon => 7,
        }
    }
    /// Crate name on disk.
    pub fn crate_name(self) -> &'static str {
        match self {
            CollectorKind::Auditd => "selfdef-collector-auditd",
            CollectorKind::Canary => "selfdef-collector-canary",
            CollectorKind::Ebpf => "selfdef-collector-ebpf",
            CollectorKind::EventStream => "selfdef-collector-eventstream",
            CollectorKind::Journald => "selfdef-collector-journald",
            CollectorKind::Suricata => "selfdef-collector-suricata",
            CollectorKind::Tetragon => "selfdef-collector-tetragon",
        }
    }
}

/// Per-collector record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CollectorEntry {
    /// Kind.
    pub kind: CollectorKind,
    /// Crate name (must match canonical).
    pub crate_name: String,
    /// Whether currently subscribed to the event-bus.
    pub subscribed: bool,
    /// Events-per-second at last sample.
    pub eps: u32,
}

/// 7-collector catalog envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CollectorCatalog {
    /// Schema version.
    pub schema_version: String,
    /// 7 entries (exactly 7).
    pub collectors: Vec<CollectorEntry>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CollectorError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 7.
    #[error("collector count {0} != 7 canonical")]
    CountInvalid(usize),
    /// Required missing.
    #[error("required collector missing: {0:?}")]
    Missing(CollectorKind),
    /// Duplicate.
    #[error("duplicate collector: {0:?}")]
    Duplicate(CollectorKind),
    /// Crate name mismatch.
    #[error("crate name mismatch for {kind:?}: declared {declared}, canonical {canonical}")]
    CrateNameMismatch {
        /// Kind.
        kind: CollectorKind,
        /// Declared.
        declared: String,
        /// Canonical.
        canonical: String,
    },
}

impl CollectorCatalog {
    /// Canonical empty catalog (all unsubscribed).
    pub fn empty_canonical() -> Self {
        let collectors = [
            CollectorKind::Auditd, CollectorKind::Canary, CollectorKind::Ebpf,
            CollectorKind::EventStream, CollectorKind::Journald,
            CollectorKind::Suricata, CollectorKind::Tetragon,
        ].into_iter().map(|k| CollectorEntry {
            kind: k,
            crate_name: k.crate_name().into(),
            subscribed: false,
            eps: 0,
        }).collect();
        Self {
            schema_version: SCHEMA_VERSION.into(),
            collectors,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CollectorError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CollectorError::SchemaMismatch);
        }
        if self.collectors.len() != 7 {
            return Err(CollectorError::CountInvalid(self.collectors.len()));
        }
        let required = [
            CollectorKind::Auditd, CollectorKind::Canary, CollectorKind::Ebpf,
            CollectorKind::EventStream, CollectorKind::Journald,
            CollectorKind::Suricata, CollectorKind::Tetragon,
        ];
        for k in required {
            if !self.collectors.iter().any(|e| e.kind == k) {
                return Err(CollectorError::Missing(k));
            }
        }
        use std::collections::HashSet;
        let mut seen: HashSet<CollectorKind> = HashSet::new();
        for e in &self.collectors {
            if !seen.insert(e.kind) {
                return Err(CollectorError::Duplicate(e.kind));
            }
            let canonical = e.kind.crate_name();
            if e.crate_name != canonical {
                return Err(CollectorError::CrateNameMismatch {
                    kind: e.kind,
                    declared: e.crate_name.clone(),
                    canonical: canonical.into(),
                });
            }
        }
        Ok(())
    }

    /// Count subscribed collectors.
    pub fn subscribed_count(&self) -> usize {
        self.collectors.iter().filter(|e| e.subscribed).count()
    }

    /// Total EPS across subscribed collectors.
    pub fn total_eps(&self) -> u64 {
        self.collectors.iter()
            .filter(|e| e.subscribed)
            .map(|e| e.eps as u64).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seven_collectors_positioned() {
        for (k, p) in [
            (CollectorKind::Auditd, 1), (CollectorKind::Canary, 2),
            (CollectorKind::Ebpf, 3), (CollectorKind::EventStream, 4),
            (CollectorKind::Journald, 5), (CollectorKind::Suricata, 6),
            (CollectorKind::Tetragon, 7),
        ] {
            assert_eq!(k.position(), p);
        }
    }

    #[test]
    fn crate_names_match_existing_workspace() {
        assert_eq!(CollectorKind::Auditd.crate_name(), "selfdef-collector-auditd");
        assert_eq!(CollectorKind::EventStream.crate_name(), "selfdef-collector-eventstream");
        assert_eq!(CollectorKind::Tetragon.crate_name(), "selfdef-collector-tetragon");
    }

    #[test]
    fn empty_canonical_validates() {
        CollectorCatalog::empty_canonical().validate().unwrap();
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = CollectorCatalog::empty_canonical();
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), CollectorError::SchemaMismatch));
    }

    #[test]
    fn count_invalid_caught() {
        let mut c = CollectorCatalog::empty_canonical();
        c.collectors.pop();
        assert!(matches!(c.validate().unwrap_err(), CollectorError::CountInvalid(6)));
    }

    #[test]
    fn crate_name_mismatch_caught() {
        let mut c = CollectorCatalog::empty_canonical();
        c.collectors[0].crate_name = "wrong".into();
        match c.validate().unwrap_err() {
            CollectorError::CrateNameMismatch { kind, declared: _, canonical: _ } => {
                assert_eq!(kind, CollectorKind::Auditd);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn subscribed_count_and_total_eps() {
        let mut c = CollectorCatalog::empty_canonical();
        c.collectors[0].subscribed = true; c.collectors[0].eps = 100;
        c.collectors[2].subscribed = true; c.collectors[2].eps = 50;
        c.collectors[4].eps = 200; // not subscribed → excluded
        assert_eq!(c.subscribed_count(), 2);
        assert_eq!(c.total_eps(), 150);
    }

    #[test]
    fn collector_serde_kebab() {
        assert_eq!(serde_json::to_string(&CollectorKind::EventStream).unwrap(), "\"event-stream\"");
        assert_eq!(serde_json::to_string(&CollectorKind::Ebpf).unwrap(), "\"ebpf\"");
    }

    #[test]
    fn catalog_serde_roundtrip() {
        let c = CollectorCatalog::empty_canonical();
        let j = serde_json::to_string(&c).unwrap();
        let back: CollectorCatalog = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
