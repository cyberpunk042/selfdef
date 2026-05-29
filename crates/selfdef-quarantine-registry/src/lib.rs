//! `selfdef-quarantine-registry` — daemon-resident, persistent registry
//! of MS042 quarantine entries. The live D-17 state the selfdef daemon
//! projects into the `selfdef-quarantine-mirror` MS007 snapshot for
//! sovereign-os to render READ-ONLY.
//!
//! Unlike grants/capability/sandbox (operator-issued), quarantine
//! entries are **daemon-populated** by MS042 declaration-vs-observed
//! detection (record_block). The operator surface is overrides only:
//! release (rehab + receipt) or forfeit (permanent denial). Same shape
//! as the sister registries — persists atomically, lifecycle transitions,
//! recompute per-severity summaries.
//!
//! Mutation lifecycle (MS042 E0430):
//!   Blocking → Quarantined → Released | Forfeited
//!                          → AutoReleased (Tier-A policy-defined cool-off)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

// Facade re-exports.
pub use selfdef_quarantine_mirror::{
    MismatchDetail, MismatchField, MismatchSeverity, QuarantineEntry, QuarantineMirrorSnapshot,
    QuarantineState, SCHEMA_VERSION, SeveritySummary,
};

/// Default on-disk path for the persisted registry (operator override
/// via `SELFDEF_QUARANTINE_PATH`).
pub const DEFAULT_STATE_PATH: &str = "/var/lib/selfdef/quarantine.json";

/// Daemon-side block report — the input the MS042 detection loop hands
/// to [`QuarantineRegistry::record_block`]. Constructed from observed
/// mismatch evidence; not an operator-signed request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockReport {
    /// Tool that was blocked.
    pub tool: String,
    /// MS003 fingerprint of the declarer (operator who signed the
    /// declaration that was violated).
    pub declarer: String,
    /// Capability-token id at time of block (MS035 linkage).
    pub capability_token_id: String,
    /// Mismatches observed (max_severity is the highest of these).
    pub mismatches: Vec<MismatchDetail>,
}

/// Operator-signed override request (release or forfeit).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OverrideRequest {
    /// Quarantine id to act on.
    pub quarantine_id: String,
    /// Operator MS003 fingerprint authorizing the override.
    pub actor: String,
    /// MS003 signature over the canonical-JSON request (hex).
    pub signature: String,
}

/// Registry errors.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Request missing the MS003 signature.
    #[error("request unsigned (MS003 signature required)")]
    Unsigned,
    /// Mandatory string field empty.
    #[error("mandatory field empty: {0}")]
    EmptyField(&'static str),
    /// `mismatches` empty — a block without observed evidence is rejected.
    #[error("block report has no mismatches (need at least one observed mismatch)")]
    EmptyMismatches,
    /// Persisted store was present but malformed.
    #[error("malformed quarantine store at {path}: {source}")]
    Malformed {
        /// Offending path.
        path: String,
        /// Parse error.
        source: serde_json::Error,
    },
    /// I/O failure on load/save.
    #[error("quarantine store io error at {path}: {source}")]
    Io {
        /// Offending path.
        path: String,
        /// I/O error.
        source: std::io::Error,
    },
    /// Timestamp formatting failed (should not happen with Rfc3339).
    #[error("timestamp format error: {0}")]
    TimeFormat(#[from] time::error::Format),
}

/// Daemon-resident quarantine registry.
#[derive(Debug, Clone)]
pub struct QuarantineRegistry {
    snapshot: QuarantineMirrorSnapshot,
}

impl Default for QuarantineRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Highest severity in a slice, defaulting to Informational when empty.
fn max_severity(mismatches: &[MismatchDetail]) -> MismatchSeverity {
    use MismatchSeverity::*;
    let mut max = Informational;
    for m in mismatches {
        max = match (max, m.severity) {
            (Critical, _) | (_, Critical) => Critical,
            (Major, _) | (_, Major) => Major,
            (Minor, _) | (_, Minor) => Minor,
            _ => Informational,
        };
    }
    max
}

impl QuarantineRegistry {
    /// New empty registry, schema pinned.
    #[must_use]
    pub fn new() -> Self {
        Self {
            snapshot: QuarantineMirrorSnapshot {
                schema_version: SCHEMA_VERSION.into(),
                captured_at: String::new(),
                summaries: Vec::new(),
                entries: Vec::new(),
                signature: String::new(),
            },
        }
    }

    /// Adopt an existing snapshot.
    #[must_use]
    pub fn from_snapshot(snapshot: QuarantineMirrorSnapshot) -> Self {
        Self { snapshot }
    }

    /// Load the persisted registry. Absent → empty; malformed → error.
    pub fn load(path: &Path) -> Result<Self, RegistryError> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::new()),
            Err(e) => {
                return Err(RegistryError::Io {
                    path: path.display().to_string(),
                    source: e,
                });
            }
        };
        let snapshot = serde_json::from_str(&text).map_err(|e| RegistryError::Malformed {
            path: path.display().to_string(),
            source: e,
        })?;
        Ok(Self { snapshot })
    }

    /// Atomically persist.
    pub fn save(&self, path: &Path) -> Result<(), RegistryError> {
        let io_err = |e: std::io::Error| RegistryError::Io {
            path: path.display().to_string(),
            source: e,
        };
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir).map_err(io_err)?;
            }
        }
        let body =
            serde_json::to_string_pretty(&self.snapshot).map_err(|e| RegistryError::Malformed {
                path: path.display().to_string(),
                source: e,
            })?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, body).map_err(io_err)?;
        std::fs::rename(&tmp, path).map_err(io_err)?;
        Ok(())
    }

    /// Daemon-side: record a block from MS042 detection. Appends a new
    /// Quarantined entry (the block has already fired; this is the
    /// post-block trace). Returns the minted quarantine id.
    pub fn record_block(
        &mut self,
        report: &BlockReport,
        quarantine_id: &str,
        trace_id: &str,
        now: OffsetDateTime,
    ) -> Result<String, RegistryError> {
        if report.tool.is_empty() {
            return Err(RegistryError::EmptyField("tool"));
        }
        if report.declarer.is_empty() {
            return Err(RegistryError::EmptyField("declarer"));
        }
        if report.capability_token_id.is_empty() {
            return Err(RegistryError::EmptyField("capability_token_id"));
        }
        if report.mismatches.is_empty() {
            return Err(RegistryError::EmptyMismatches);
        }
        let stamp = now.format(&Rfc3339)?;
        let max_sev = max_severity(&report.mismatches);
        let entry = QuarantineEntry {
            quarantine_id: quarantine_id.to_string(),
            tool: report.tool.clone(),
            declarer: report.declarer.clone(),
            capability_token_id: report.capability_token_id.clone(),
            blocked_at: stamp.clone(),
            updated_at: stamp,
            state: QuarantineState::Quarantined,
            max_severity: max_sev,
            mismatches: report.mismatches.clone(),
            trace_id: trace_id.to_string(),
            signature: String::new(), // daemon-populated; not operator-signed
        };
        self.snapshot.entries.push(entry);
        self.recompute(now)?;
        Ok(quarantine_id.to_string())
    }

    /// Operator-signed release (rehab). Returns true if found.
    pub fn release(
        &mut self,
        req: &OverrideRequest,
        now: OffsetDateTime,
    ) -> Result<bool, RegistryError> {
        self.apply_override(req, QuarantineState::Released, now)
    }

    /// Operator-signed forfeit (permanent denial). Returns true if found.
    pub fn forfeit(
        &mut self,
        req: &OverrideRequest,
        now: OffsetDateTime,
    ) -> Result<bool, RegistryError> {
        self.apply_override(req, QuarantineState::Forfeited, now)
    }

    fn apply_override(
        &mut self,
        req: &OverrideRequest,
        state: QuarantineState,
        now: OffsetDateTime,
    ) -> Result<bool, RegistryError> {
        if req.signature.is_empty() {
            return Err(RegistryError::Unsigned);
        }
        if req.actor.is_empty() {
            return Err(RegistryError::EmptyField("actor"));
        }
        let stamp = now.format(&Rfc3339)?;
        let mut hit = false;
        for e in &mut self.snapshot.entries {
            if e.quarantine_id == req.quarantine_id {
                e.state = state;
                e.updated_at = stamp.clone();
                // Update entry signature to the operator's override sig.
                e.signature = req.signature.clone();
                hit = true;
                break;
            }
        }
        if hit {
            self.recompute(now)?;
        }
        Ok(hit)
    }

    fn recompute(&mut self, now: OffsetDateTime) -> Result<(), RegistryError> {
        self.snapshot.summaries = self.snapshot.recompute_summaries();
        self.snapshot.captured_at = now.format(&Rfc3339)?;
        Ok(())
    }

    /// Current published snapshot.
    #[must_use]
    pub fn snapshot(&self) -> &QuarantineMirrorSnapshot {
        &self.snapshot
    }

    /// Live entries.
    #[must_use]
    pub fn entries(&self) -> &[QuarantineEntry] {
        &self.snapshot.entries
    }

    /// Count of entries currently Quarantined.
    #[must_use]
    pub fn quarantined_count(&self) -> usize {
        self.snapshot.quarantined_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn mismatch(sev: MismatchSeverity) -> MismatchDetail {
        MismatchDetail {
            field: MismatchField::ReadPaths,
            declared: "/safe".into(),
            observed: "/etc/passwd".into(),
            first_observed_at: "2027-01-15T07:59:00Z".into(),
            severity: sev,
        }
    }

    fn report() -> BlockReport {
        BlockReport {
            tool: "rg".into(),
            declarer: "operator-fp".into(),
            capability_token_id: "tok-1".into(),
            mismatches: vec![mismatch(MismatchSeverity::Critical)],
        }
    }

    fn override_req(qid: &str) -> OverrideRequest {
        OverrideRequest {
            quarantine_id: qid.into(),
            actor: "operator-fp".into(),
            signature: "ms003-sig".into(),
        }
    }

    #[test]
    fn new_is_empty_and_schema_pinned() {
        let r = QuarantineRegistry::new();
        assert!(r.entries().is_empty());
        assert_eq!(r.snapshot().schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn record_block_appends_quarantined_entry() {
        let mut r = QuarantineRegistry::new();
        r.record_block(&report(), "q-1", "t1", now()).unwrap();
        let e = &r.entries()[0];
        assert_eq!(e.state, QuarantineState::Quarantined);
        assert_eq!(e.max_severity, MismatchSeverity::Critical);
        assert_eq!(e.blocked_at, "2027-01-15T08:00:00Z");
        assert_eq!(e.tool, "rg");
        assert_eq!(r.quarantined_count(), 1);
    }

    #[test]
    fn record_block_rejects_empty_mismatches() {
        let mut r = QuarantineRegistry::new();
        let mut bad = report();
        bad.mismatches.clear();
        assert!(matches!(
            r.record_block(&bad, "q", "t", now()).unwrap_err(),
            RegistryError::EmptyMismatches
        ));
    }

    #[test]
    fn record_block_rejects_empty_required_fields() {
        let mut r = QuarantineRegistry::new();
        let mut bad = report();
        bad.tool = String::new();
        assert!(matches!(
            r.record_block(&bad, "q", "t", now()).unwrap_err(),
            RegistryError::EmptyField("tool")
        ));
    }

    #[test]
    fn record_block_picks_highest_severity() {
        let mut r = QuarantineRegistry::new();
        let mut rep = report();
        rep.mismatches = vec![
            mismatch(MismatchSeverity::Minor),
            mismatch(MismatchSeverity::Major),
            mismatch(MismatchSeverity::Minor),
        ];
        r.record_block(&rep, "q-1", "t1", now()).unwrap();
        assert_eq!(r.entries()[0].max_severity, MismatchSeverity::Major);
    }

    #[test]
    fn release_transitions_to_released() {
        let mut r = QuarantineRegistry::new();
        r.record_block(&report(), "q-1", "t1", now()).unwrap();
        assert!(r.release(&override_req("q-1"), now()).unwrap());
        assert_eq!(r.entries()[0].state, QuarantineState::Released);
        // Operator signature now carried.
        assert_eq!(r.entries()[0].signature, "ms003-sig");
    }

    #[test]
    fn forfeit_transitions_to_forfeited() {
        let mut r = QuarantineRegistry::new();
        r.record_block(&report(), "q-1", "t1", now()).unwrap();
        assert!(r.forfeit(&override_req("q-1"), now()).unwrap());
        assert_eq!(r.entries()[0].state, QuarantineState::Forfeited);
    }

    #[test]
    fn override_unknown_id_returns_false() {
        let mut r = QuarantineRegistry::new();
        assert!(!r.release(&override_req("nope"), now()).unwrap());
        assert!(!r.forfeit(&override_req("nope"), now()).unwrap());
    }

    #[test]
    fn override_rejects_unsigned() {
        let mut r = QuarantineRegistry::new();
        r.record_block(&report(), "q-1", "t1", now()).unwrap();
        let mut bad = override_req("q-1");
        bad.signature = String::new();
        assert!(matches!(
            r.release(&bad, now()).unwrap_err(),
            RegistryError::Unsigned
        ));
    }

    #[test]
    fn save_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("quarantine.json");
        let mut r = QuarantineRegistry::new();
        r.record_block(&report(), "q-1", "t1", now()).unwrap();
        r.release(&override_req("q-1"), now()).unwrap();
        r.save(&path).unwrap();
        assert!(!path.with_extension("json.tmp").exists());
        let back = QuarantineRegistry::load(&path).unwrap();
        assert_eq!(back.entries().len(), 1);
        assert_eq!(back.entries()[0].state, QuarantineState::Released);
        back.snapshot().validate_schema().unwrap();
    }

    #[test]
    fn load_absent_is_empty_not_error() {
        let dir = tempfile::tempdir().unwrap();
        let r = QuarantineRegistry::load(&dir.path().join("nope.json")).unwrap();
        assert!(r.entries().is_empty());
    }
}
