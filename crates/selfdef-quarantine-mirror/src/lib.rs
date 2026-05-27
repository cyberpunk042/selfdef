//! `selfdef-quarantine-mirror` — MS007 typed-mirror crate exposing
//! selfdef MS042 quarantined tools (declaration-vs-observed mismatch)
//! READ-ONLY for sovereign-os D-17 quarantine dashboard.
//!
//! Per MS043 R10187 + R10193, mirrors expose state read-only; release
//! decisions proxy via MS003-signed operator request only.
//!
//! Composes with:
//! - MS042 declaration-vs-observed discipline (block + quarantine + trace per E0430)
//! - MS037 fanotify (observed filesystem paths)
//! - MS038 eBPF (observed network domains)
//! - MS036 sandbox tiers (post-quarantine escalation target)
//! - MS041 commit authority (release receipt requires L5 Commit)
//!
//! The 7 declaration fields per E0429 + dump 17422-17432:
//! 1. read_paths
//! 2. write_paths
//! 3. network_domains
//! 4. env_vars
//! 5. secret_access
//! 6. side_effects
//! 7. rollback
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version. Bump on breaking changes; consumers MUST refuse
/// unknown major versions.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Which of the 7 declaration fields had a declaration-vs-observed mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MismatchField {
    /// Read paths beyond declaration.
    ReadPaths,
    /// Write paths beyond declaration.
    WritePaths,
    /// Network domains beyond declaration.
    NetworkDomains,
    /// Environment variable access beyond declaration.
    EnvVars,
    /// Secret access (kernel keyring) beyond declaration.
    SecretAccess,
    /// Side-effect (file write / process spawn / persistent change) beyond declaration.
    SideEffects,
    /// Rollback declaration cannot satisfy committed side-effect.
    Rollback,
}

/// Quarantine entry lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineState {
    /// Block in flight — tool process being terminated.
    Blocking,
    /// Active quarantine — tool isolated, trace ongoing, awaiting triage.
    Quarantined,
    /// Operator-released — full rehab + MS003-signed release receipt.
    Released,
    /// Operator-forfeited — tool permanently denied, image purged.
    Forfeited,
    /// Auto-released after policy-defined cool-off (rare; only Tier A tools).
    AutoReleased,
}

/// Severity of the mismatch per MS042 E0430.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MismatchSeverity {
    /// Declaration superset of observed — informational only, not blocking.
    Informational,
    /// Minor scope drift (e.g. read-only path drift to read-only sibling).
    Minor,
    /// Major scope drift (e.g. declared file-only, observed network egress).
    Major,
    /// Critical — declared read-only, observed write or secret access.
    Critical,
}

/// Single observed mismatch detail.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MismatchDetail {
    /// Which declaration field was violated.
    pub field: MismatchField,
    /// Declared value (canonical-JSON string).
    pub declared: String,
    /// Observed value (canonical-JSON string).
    pub observed: String,
    /// ISO-8601 UTC when first observed.
    pub first_observed_at: String,
    /// Severity classification.
    pub severity: MismatchSeverity,
}

/// Single quarantine entry. Wire-stable for D-17 rendering.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuarantineEntry {
    /// Selfdef-internal quarantine id (ULID).
    pub quarantine_id: String,
    /// Tool name that was quarantined.
    pub tool: String,
    /// MS003 fingerprint of the tool declaration signer.
    pub declarer: String,
    /// Originating capability_token_id at time of block.
    pub capability_token_id: String,
    /// ISO-8601 UTC timestamp when block fired.
    pub blocked_at: String,
    /// ISO-8601 UTC timestamp of last state transition.
    pub updated_at: String,
    /// Current state.
    pub state: QuarantineState,
    /// Highest-severity mismatch observed.
    pub max_severity: MismatchSeverity,
    /// All mismatch details collected before block.
    pub mismatches: Vec<MismatchDetail>,
    /// M049 trace_id tying back to the failing span.
    pub trace_id: String,
    /// MS003 signature on the quarantine receipt envelope (hex).
    pub signature: String,
}

/// Aggregate counts by severity for D-17 top-line tiles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeveritySummary {
    /// Severity bucket.
    pub severity: MismatchSeverity,
    /// Count currently in Quarantined state with this max-severity.
    pub quarantined: u32,
    /// Count Released in last 24h.
    pub released_24h: u32,
    /// Count Forfeited in last 24h.
    pub forfeited_24h: u32,
}

/// Top-level mirror snapshot consumed by sovereign-os D-17 dashboard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuarantineMirrorSnapshot {
    /// Wire-stable schema version. MUST equal [`SCHEMA_VERSION`].
    pub schema_version: String,
    /// ISO-8601 UTC timestamp when snapshot was captured.
    pub captured_at: String,
    /// Per-severity tiles.
    pub summaries: Vec<SeveritySummary>,
    /// Full quarantine list (active + recent history).
    pub entries: Vec<QuarantineEntry>,
    /// MS003 signature over the canonical-JSON encoding.
    pub signature: String,
}

/// Errors a consumer may surface when reading this mirror.
#[derive(Debug, Error)]
pub enum MirrorError {
    /// Schema major version mismatch.
    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected version.
        expected: String,
        /// Observed version.
        actual: String,
    },
    /// MS003 signature verification failed.
    #[error("MS003 signature verification failed: {0}")]
    SignatureFailed(String),
    /// Snapshot was empty when consumer expected populated data.
    #[error("snapshot is empty (publisher may be initializing)")]
    EmptySnapshot,
    /// Deserialization failure.
    #[error("snapshot deserialization failed: {0}")]
    Deserialize(String),
}

impl QuarantineMirrorSnapshot {
    /// Validate schema version. Same-major bumps OK per M061 R10297.
    pub fn validate_schema(&self) -> Result<(), MirrorError> {
        if self.schema_version == SCHEMA_VERSION {
            return Ok(());
        }
        let snap_major = self.schema_version.split('.').next().unwrap_or("");
        let exp_major = SCHEMA_VERSION.split('.').next().unwrap_or("");
        if snap_major != exp_major {
            return Err(MirrorError::SchemaMismatch {
                expected: SCHEMA_VERSION.into(),
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }

    /// Count entries currently in Quarantined state.
    pub fn quarantined_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.state == QuarantineState::Quarantined)
            .count()
    }

    /// Count entries by current state.
    pub fn state_counts(&self) -> std::collections::HashMap<QuarantineState, u32> {
        use std::collections::HashMap;
        let mut m: HashMap<QuarantineState, u32> = HashMap::new();
        for e in &self.entries {
            *m.entry(e.state).or_insert(0) += 1;
        }
        m
    }

    /// Aggregate entries by max severity. Read-only cross-check helper.
    pub fn recompute_summaries(&self) -> Vec<SeveritySummary> {
        use std::collections::HashMap;
        let mut by_sev: HashMap<MismatchSeverity, SeveritySummary> = HashMap::new();
        for e in &self.entries {
            let entry = by_sev.entry(e.max_severity).or_insert(SeveritySummary {
                severity: e.max_severity,
                quarantined: 0,
                released_24h: 0,
                forfeited_24h: 0,
            });
            match e.state {
                QuarantineState::Quarantined | QuarantineState::Blocking => entry.quarantined += 1,
                QuarantineState::Released | QuarantineState::AutoReleased => {
                    entry.released_24h += 1
                }
                QuarantineState::Forfeited => entry.forfeited_24h += 1,
            }
        }
        let mut out: Vec<SeveritySummary> = by_sev.into_values().collect();
        // Sort severity descending (critical first)
        out.sort_by_key(|s| match s.severity {
            MismatchSeverity::Critical => 0,
            MismatchSeverity::Major => 1,
            MismatchSeverity::Minor => 2,
            MismatchSeverity::Informational => 3,
        });
        out
    }

    /// Total mismatch detail count across entries.
    pub fn total_mismatches(&self) -> usize {
        self.entries.iter().map(|e| e.mismatches.len()).sum()
    }

    /// Find which declaration fields contribute most to mismatches.
    /// Returns sorted (field, count) descending.
    pub fn top_mismatch_fields(&self) -> Vec<(MismatchField, u32)> {
        use std::collections::HashMap;
        let mut m: HashMap<MismatchField, u32> = HashMap::new();
        for e in &self.entries {
            for d in &e.mismatches {
                *m.entry(d.field).or_insert(0) += 1;
            }
        }
        let mut v: Vec<(MismatchField, u32)> = m.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_entry(
        id: &str,
        state: QuarantineState,
        sev: MismatchSeverity,
        fields: &[MismatchField],
    ) -> QuarantineEntry {
        let mismatches: Vec<MismatchDetail> = fields
            .iter()
            .map(|&f| MismatchDetail {
                field: f,
                declared: "ro_path:/etc".into(),
                observed: "rw_path:/etc:write".into(),
                first_observed_at: "2026-05-19T03:00:00Z".into(),
                severity: sev,
            })
            .collect();
        QuarantineEntry {
            quarantine_id: id.into(),
            tool: "untrusted-binary".into(),
            declarer: "ext-fp".into(),
            capability_token_id: format!("cap-{id}"),
            blocked_at: "2026-05-19T03:00:00Z".into(),
            updated_at: "2026-05-19T03:15:00Z".into(),
            state,
            max_severity: sev,
            mismatches,
            trace_id: format!("trace-{id}"),
            signature: format!("sig-{id}"),
        }
    }

    #[test]
    fn schema_validates_canonical() {
        let snap = QuarantineMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            summaries: vec![],
            entries: vec![],
            signature: String::new(),
        };
        snap.validate_schema().unwrap();
    }

    #[test]
    fn schema_rejects_major_drift() {
        let snap = QuarantineMirrorSnapshot {
            schema_version: "2.0.0".into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            summaries: vec![],
            entries: vec![],
            signature: String::new(),
        };
        assert!(matches!(
            snap.validate_schema().unwrap_err(),
            MirrorError::SchemaMismatch { .. }
        ));
    }

    #[test]
    fn quarantined_count_filters_state() {
        let snap = QuarantineMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            summaries: vec![],
            entries: vec![
                mk_entry(
                    "a",
                    QuarantineState::Quarantined,
                    MismatchSeverity::Major,
                    &[MismatchField::NetworkDomains],
                ),
                mk_entry(
                    "b",
                    QuarantineState::Released,
                    MismatchSeverity::Minor,
                    &[MismatchField::ReadPaths],
                ),
                mk_entry(
                    "c",
                    QuarantineState::Quarantined,
                    MismatchSeverity::Critical,
                    &[MismatchField::SecretAccess],
                ),
                mk_entry(
                    "d",
                    QuarantineState::Forfeited,
                    MismatchSeverity::Critical,
                    &[MismatchField::WritePaths],
                ),
            ],
            signature: String::new(),
        };
        assert_eq!(snap.quarantined_count(), 2);
    }

    #[test]
    fn state_counts_returns_all_states() {
        let snap = QuarantineMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            summaries: vec![],
            entries: vec![
                mk_entry(
                    "a",
                    QuarantineState::Quarantined,
                    MismatchSeverity::Major,
                    &[MismatchField::NetworkDomains],
                ),
                mk_entry(
                    "b",
                    QuarantineState::Quarantined,
                    MismatchSeverity::Major,
                    &[MismatchField::NetworkDomains],
                ),
                mk_entry(
                    "c",
                    QuarantineState::Released,
                    MismatchSeverity::Minor,
                    &[MismatchField::ReadPaths],
                ),
                mk_entry(
                    "d",
                    QuarantineState::Forfeited,
                    MismatchSeverity::Critical,
                    &[MismatchField::WritePaths],
                ),
            ],
            signature: String::new(),
        };
        let m = snap.state_counts();
        assert_eq!(m[&QuarantineState::Quarantined], 2);
        assert_eq!(m[&QuarantineState::Released], 1);
        assert_eq!(m[&QuarantineState::Forfeited], 1);
    }

    #[test]
    fn recompute_summaries_groups_by_severity_descending() {
        let snap = QuarantineMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            summaries: vec![],
            entries: vec![
                mk_entry(
                    "a",
                    QuarantineState::Quarantined,
                    MismatchSeverity::Critical,
                    &[MismatchField::SecretAccess],
                ),
                mk_entry(
                    "b",
                    QuarantineState::Quarantined,
                    MismatchSeverity::Major,
                    &[MismatchField::NetworkDomains],
                ),
                mk_entry(
                    "c",
                    QuarantineState::Released,
                    MismatchSeverity::Minor,
                    &[MismatchField::ReadPaths],
                ),
            ],
            signature: String::new(),
        };
        let s = snap.recompute_summaries();
        assert_eq!(s.len(), 3);
        assert_eq!(s[0].severity, MismatchSeverity::Critical);
        assert_eq!(s[1].severity, MismatchSeverity::Major);
        assert_eq!(s[2].severity, MismatchSeverity::Minor);
        assert_eq!(s[0].quarantined, 1);
        assert_eq!(s[2].released_24h, 1);
    }

    #[test]
    fn top_mismatch_fields_sorts_descending() {
        let snap = QuarantineMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            summaries: vec![],
            entries: vec![
                mk_entry(
                    "a",
                    QuarantineState::Quarantined,
                    MismatchSeverity::Major,
                    &[
                        MismatchField::NetworkDomains,
                        MismatchField::NetworkDomains,
                        MismatchField::WritePaths,
                    ],
                ),
                mk_entry(
                    "b",
                    QuarantineState::Quarantined,
                    MismatchSeverity::Major,
                    &[MismatchField::NetworkDomains, MismatchField::SecretAccess],
                ),
            ],
            signature: String::new(),
        };
        let top = snap.top_mismatch_fields();
        assert_eq!(top[0].0, MismatchField::NetworkDomains);
        assert_eq!(top[0].1, 3);
        assert!(top.iter().any(|(f, _)| *f == MismatchField::WritePaths));
        assert!(top.iter().any(|(f, _)| *f == MismatchField::SecretAccess));
    }

    #[test]
    fn total_mismatches_sums_all_details() {
        let snap = QuarantineMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            summaries: vec![],
            entries: vec![
                mk_entry(
                    "a",
                    QuarantineState::Quarantined,
                    MismatchSeverity::Major,
                    &[MismatchField::NetworkDomains, MismatchField::WritePaths],
                ),
                mk_entry(
                    "b",
                    QuarantineState::Released,
                    MismatchSeverity::Minor,
                    &[MismatchField::ReadPaths],
                ),
            ],
            signature: String::new(),
        };
        assert_eq!(snap.total_mismatches(), 3);
    }

    #[test]
    fn entry_serde_roundtrip_preserves_mismatches() {
        let original = mk_entry(
            "alpha",
            QuarantineState::Quarantined,
            MismatchSeverity::Critical,
            &[MismatchField::SecretAccess, MismatchField::WritePaths],
        );
        let j = serde_json::to_string(&original).unwrap();
        let back: QuarantineEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(original, back);
        assert_eq!(back.mismatches.len(), 2);
        assert_eq!(back.mismatches[0].field, MismatchField::SecretAccess);
    }

    #[test]
    fn mismatch_field_serde_uses_snake_case() {
        let j = serde_json::to_string(&MismatchField::SecretAccess).unwrap();
        assert_eq!(j, "\"secret_access\"");
    }

    #[test]
    fn quarantine_state_serde_uses_snake_case() {
        let j = serde_json::to_string(&QuarantineState::AutoReleased).unwrap();
        assert_eq!(j, "\"auto_released\"");
    }

    #[test]
    fn mismatch_severity_serde_uses_snake_case() {
        let j = serde_json::to_string(&MismatchSeverity::Informational).unwrap();
        assert_eq!(j, "\"informational\"");
    }
}
