//! `selfdef-scheduler::decision_audit` — M01170: Append-only ZFS-resident
//! audit log for `BackpressureDriver` observations.
//!
//! Dump grounding (avx-plus-plus 2026-05-18 line 18307):
//! > *"ZFS remembers."*
//!
//! Catalog grounding: MS048 module `M01170 selfdef-scheduler-decision-
//! audit` per `~/selfdef/backlog/milestones/MS048-goldilocks-scheduler-
//! hardware-aware-resource-routing.md`. Extends the existing
//! `crate::emit_audit_entry` (which handles `Decision` records) with a
//! parallel persistence layer for `DriverReading` observations.
//!
//! Doctrinal anchor: [Peace Machine + Core Law](https://github.com/
//! cyberpunk042/devops-solutions-information-hub/blob/main/wiki/spine/
//! doctrine/peace-machine-and-core-law.md) — Core Law clause
//! "ZFS remembers" (MS048 owns the Runtime-routes clause; M01170 owns
//! the durability + integrity guarantees of WHAT is remembered).
//!
//! ## What this module provides
//!
//! 1. `emit_driver_reading(audit_log, &DriverReading, signer_kid)` —
//!    SHA-256-chained append of a `DriverReading` to the audit log.
//!    Each entry's `prev_event_sha256` is the SHA-256 of the
//!    previous line's bytes (parallel to `emit_audit_entry` for
//!    `Decision` records). MS003-multisig hook: `signer_kid` is
//!    embedded so a future signer process can co-sign entries
//!    without changing the wire format.
//! 2. `rotate_audit_log(path, max_bytes, max_generations)` — atomic
//!    rotation policy: when `path` exceeds `max_bytes`, shift
//!    `.1`→`.2`, `.2`→`.3`, ..., (drop generation `max_generations`),
//!    then mv current → `.1` and create a fresh empty `path`. Uses
//!    `rename(2)` so the rotation is atomic at the per-file level.
//! 3. `verify_chain(audit_log) -> Result<ChainStats>` — parses every
//!    line, verifies SHA-256 chain integrity, returns count + first +
//!    last timestamp. Detects chain breaks, malformed JSON, missing
//!    required fields.
//! 4. `verify_chain_across_generations(base_path)` — walks `.N+1` →
//!    `.N` → ... → `.1` → `base_path` and verifies the chain stays
//!    continuous across rotations.
//! 5. `ChainStats` — { event_count, first_ts_unix_micros,
//!    last_ts_unix_micros, last_sha256 }. Operator surfaces this in
//!    the audit-verification cli + cockpit panel.
//! 6. `DriverAuditEntry` — typed envelope for the JSON-Lines event,
//!    with `serde` round-trip for replay tooling.
//!
//! ## Why a parallel emit (not just reuse emit_audit_entry)
//!
//! `Decision` and `DriverReading` describe different things at
//! different cadences: `Decision` is per-request routing output
//! (low-frequency, 1 per scheduled request); `DriverReading` is
//! per-poll substrate observation (60s cadence, no request boundary).
//! Conflating them into one stream would (a) make replay-against-
//! alternate-profile (existing `crate::replay`) noisier, and
//! (b) break operator mental model. Two parallel streams in two
//! files keep the audit shape clean. SHA-256 chain semantics are
//! IDENTICAL across both — operators can verify either stream with
//! the same algorithm.
//!
//! ## Non-goals
//!
//! - Not a multisig signer. `signer_kid` is embedded; actual
//!   signature generation is M01172 (selfdef-scheduler-policy-
//!   signer) — separate slot.
//! - Not a remote-replication layer. ZFS send/recv lives in
//!   sovereign-os; this module produces the local stream that
//!   gets replicated.
//! - Not a query engine. JSONL is the wire format; SIEM tooling
//!   queries it via grep / jq / similar.
//!
//! Standing rule: We do not minimize anything.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::backpressure_driver::DriverReading;

/// Default audit log path. Sized to fit within ZFS `tank/vault/context`.
pub const DEFAULT_DRIVER_AUDIT_PATH: &str = "/var/log/selfdef/scheduler.driver.audit.jsonl";

/// Default rotation threshold (64 MiB) — operationally similar to
/// logrotate's default + small enough to fit comfortably in operator
/// memory for a `verify_chain` pass.
pub const DEFAULT_ROTATE_BYTES: u64 = 64 * 1024 * 1024;

/// Default rotation generation cap (10 = current + .1..=.10 = 11 files).
pub const DEFAULT_MAX_GENERATIONS: u32 = 10;

/// Schema version embedded in every emitted entry.
pub const DRIVER_AUDIT_SCHEMA_VERSION: &str = "1.0.0";

// ============================================================================
// Errors
// ============================================================================

/// Errors emitted by this module.
#[derive(Debug, Error)]
pub enum DriverAuditError {
    /// IO error reading/writing the audit log.
    #[error("audit io ({path}): {source}")]
    Io {
        /// Path that failed.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// JSON serialize/deserialize failure.
    #[error("audit serde: {0}")]
    Serde(String),
    /// SHA-256 chain integrity violated.
    #[error("audit chain break at line {line}: {detail}")]
    ChainBreak {
        /// 1-based line number where the break was detected.
        line: usize,
        /// Human reason.
        detail: String,
    },
}

// ============================================================================
// DriverAuditEntry — wire shape
// ============================================================================

/// Typed envelope for one JSONL line. Mirrors the JSON shape
/// `emit_driver_reading` writes; enables `verify_chain` to round-
/// trip without ad-hoc field plucking.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DriverAuditEntry {
    /// Schema version of THIS entry (not of the file).
    pub schema_version: String,
    /// Wall-clock unix microseconds when the reading was captured.
    pub captured_at_unix_micros: u128,
    /// Full embedded reading (serde round-trips the production shape).
    pub reading: DriverReading,
    /// MS003-multisig signer key id placeholder. `None` = unsigned
    /// (development / first-boot); `Some(kid)` = the kid the future
    /// signer process will use when co-signing.
    pub signer_kid: Option<String>,
    /// SHA-256 of the PREVIOUS line's bytes. `None` for the first
    /// entry; `Some(hex)` for subsequent entries.
    pub prev_event_sha256: Option<String>,
}

// ============================================================================
// emit_driver_reading
// ============================================================================

/// Append a `DriverReading` to the audit log with SHA-256 chain
/// linkage to the previous entry. Creates parent dirs + file if
/// absent. O_APPEND + fsync for durability.
///
/// # Errors
///
/// Returns [`DriverAuditError`] on IO, JSON, or chain-derivation
/// failure.
pub fn emit_driver_reading(
    audit_log: &Path,
    reading: &DriverReading,
    signer_kid: Option<&str>,
) -> Result<DriverAuditEntry, DriverAuditError> {
    if let Some(parent) = audit_log.parent() {
        fs::create_dir_all(parent).map_err(|source| DriverAuditError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let prev_sha = last_line_sha256(audit_log)?;
    let entry = DriverAuditEntry {
        schema_version: DRIVER_AUDIT_SCHEMA_VERSION.to_string(),
        captured_at_unix_micros: reading.captured_at_unix_micros,
        reading: reading.clone(),
        signer_kid: signer_kid.map(str::to_owned),
        prev_event_sha256: prev_sha,
    };
    let line = serde_json::to_string(&entry).map_err(|e| DriverAuditError::Serde(e.to_string()))?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit_log)
        .map_err(|source| DriverAuditError::Io {
            path: audit_log.to_path_buf(),
            source,
        })?;
    writeln!(file, "{line}").map_err(|source| DriverAuditError::Io {
        path: audit_log.to_path_buf(),
        source,
    })?;
    file.sync_all().map_err(|source| DriverAuditError::Io {
        path: audit_log.to_path_buf(),
        source,
    })?;
    Ok(entry)
}

fn last_line_sha256(path: &Path) -> Result<Option<String>, DriverAuditError> {
    // Read from `path` first; if absent or empty, fall back to the most
    // recent rotated generation (.1, .2, ...) so chain continuity holds
    // across `rotate_audit_log()` boundaries. Without this fallback,
    // the entry written immediately after rotation would have
    // prev_event_sha256=None, breaking `verify_chain_across_generations`.
    if let Some(sha) = last_line_sha256_in(path)? {
        return Ok(Some(sha));
    }
    // Probe rotated generations in order .1 → .DEFAULT_MAX_GENERATIONS.
    // Bounded loop; never traverses beyond the documented cap.
    for n in 1..=DEFAULT_MAX_GENERATIONS {
        let gen_path = generation_path(path, n);
        if let Some(sha) = last_line_sha256_in(&gen_path)? {
            return Ok(Some(sha));
        }
    }
    Ok(None)
}

fn last_line_sha256_in(path: &Path) -> Result<Option<String>, DriverAuditError> {
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(path).map_err(|source| DriverAuditError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let last = text.lines().filter(|l| !l.trim().is_empty()).next_back();
    match last {
        None => Ok(None),
        Some(line) => {
            let mut h = Sha256::new();
            h.update(line.as_bytes());
            Ok(Some(format!("{:x}", h.finalize())))
        }
    }
}

// ============================================================================
// rotate_audit_log
// ============================================================================

/// Rotate the audit log if it exceeds `max_bytes`. Generations:
/// `path.1` (most recent rotation), `path.2`, ..., `path.<max_generations>`.
///
/// Returns `Ok(true)` if rotation happened, `Ok(false)` if the file
/// was under threshold (or absent).
///
/// # Errors
///
/// Returns [`DriverAuditError::Io`] on any rename/remove failure.
pub fn rotate_audit_log(
    path: &Path,
    max_bytes: u64,
    max_generations: u32,
) -> Result<bool, DriverAuditError> {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return Ok(false), // file doesn't exist; nothing to rotate
    };
    if meta.len() < max_bytes {
        return Ok(false);
    }
    // Drop the oldest generation if it exists.
    let oldest = generation_path(path, max_generations);
    if oldest.exists() {
        fs::remove_file(&oldest).map_err(|source| DriverAuditError::Io {
            path: oldest.clone(),
            source,
        })?;
    }
    // Shift .(N-1) → .N, ..., .1 → .2.
    for n in (1..max_generations).rev() {
        let from = generation_path(path, n);
        let to = generation_path(path, n + 1);
        if from.exists() {
            fs::rename(&from, &to).map_err(|source| DriverAuditError::Io {
                path: from.clone(),
                source,
            })?;
        }
    }
    // mv current → .1.
    let one = generation_path(path, 1);
    fs::rename(path, &one).map_err(|source| DriverAuditError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    // Create fresh empty file at the canonical path.
    fs::File::create(path).map_err(|source| DriverAuditError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(true)
}

fn generation_path(base: &Path, n: u32) -> PathBuf {
    let mut s = base.as_os_str().to_owned();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}

// ============================================================================
// verify_chain + ChainStats
// ============================================================================

/// Statistics from a `verify_chain` pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainStats {
    /// Number of entries seen.
    pub event_count: usize,
    /// `captured_at_unix_micros` of the FIRST entry (None if file empty).
    pub first_ts_unix_micros: Option<u128>,
    /// `captured_at_unix_micros` of the LAST entry.
    pub last_ts_unix_micros: Option<u128>,
    /// SHA-256 of the last line's bytes (None if file empty). Operators
    /// use this for ZFS send/recv replication validation.
    pub last_sha256: Option<String>,
}

impl ChainStats {
    /// Empty stats (file absent or empty).
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            event_count: 0,
            first_ts_unix_micros: None,
            last_ts_unix_micros: None,
            last_sha256: None,
        }
    }
}

/// Verify SHA-256 chain integrity of `audit_log`. Returns `ChainStats`.
///
/// # Errors
///
/// Returns [`DriverAuditError::ChainBreak`] on any chain violation or
/// malformed entry; [`DriverAuditError::Io`] on read failure.
pub fn verify_chain(audit_log: &Path) -> Result<ChainStats, DriverAuditError> {
    if !audit_log.exists() {
        return Ok(ChainStats::empty());
    }
    let text = fs::read_to_string(audit_log).map_err(|source| DriverAuditError::Io {
        path: audit_log.to_path_buf(),
        source,
    })?;
    verify_chain_text(&text, None)
}

/// Internal: verify the chain in `text`, expecting the FIRST entry's
/// `prev_event_sha256` to equal `expected_first_prev_sha`. Used by
/// `verify_chain` (with `None`) and by `verify_chain_across_generations`
/// (with the prior file's last_sha256).
fn verify_chain_text(
    text: &str,
    expected_first_prev_sha: Option<&str>,
) -> Result<ChainStats, DriverAuditError> {
    let mut last_sha: Option<String> = expected_first_prev_sha.map(str::to_owned);
    let mut first_ts: Option<u128> = None;
    let mut last_ts: Option<u128> = None;
    let mut events = 0usize;
    let mut is_first = true;
    for (idx, raw_line) in text.lines().enumerate() {
        let line_no = idx + 1;
        if raw_line.trim().is_empty() {
            continue;
        }
        let entry: DriverAuditEntry =
            serde_json::from_str(raw_line).map_err(|e| DriverAuditError::ChainBreak {
                line: line_no,
                detail: format!("malformed json: {e}"),
            })?;
        // First entry in the file is allowed prev_event_sha256=None
        // ONLY when no expected_first_prev_sha was provided (i.e.
        // this is the genesis file). Otherwise the expected value
        // is the previous file's last_sha256.
        match (&last_sha, &entry.prev_event_sha256) {
            (Some(want), Some(got)) if want != got => {
                return Err(DriverAuditError::ChainBreak {
                    line: line_no,
                    detail: format!("prev_event_sha256={got}, expected {want}"),
                });
            }
            (Some(_), None) => {
                return Err(DriverAuditError::ChainBreak {
                    line: line_no,
                    detail: "prev_event_sha256 missing from non-genesis entry".into(),
                });
            }
            (None, Some(_)) if is_first => {
                return Err(DriverAuditError::ChainBreak {
                    line: line_no,
                    detail: "prev_event_sha256 present on genesis entry (expected None)".into(),
                });
            }
            _ => {}
        }
        if first_ts.is_none() {
            first_ts = Some(entry.captured_at_unix_micros);
        }
        last_ts = Some(entry.captured_at_unix_micros);
        let mut h = Sha256::new();
        h.update(raw_line.as_bytes());
        last_sha = Some(format!("{:x}", h.finalize()));
        events += 1;
        is_first = false;
    }
    Ok(ChainStats {
        event_count: events,
        first_ts_unix_micros: first_ts,
        last_ts_unix_micros: last_ts,
        last_sha256: last_sha,
    })
}

/// Verify chain integrity ACROSS rotation generations. Walks the
/// oldest existing generation (`base_path.<max_generations>`) down to
/// the current `base_path`, verifying that the chain is continuous
/// across rotations.
///
/// # Errors
///
/// Returns [`DriverAuditError`] as `verify_chain` does, with the
/// `line` field referring to the offending file's line number.
pub fn verify_chain_across_generations(
    base_path: &Path,
    max_generations: u32,
) -> Result<ChainStats, DriverAuditError> {
    let mut overall = ChainStats::empty();
    let mut expected_prev: Option<String> = None;
    let mut files: Vec<PathBuf> = Vec::new();
    // Walk oldest → newest.
    for n in (1..=max_generations).rev() {
        let p = generation_path(base_path, n);
        if p.exists() {
            files.push(p);
        }
    }
    if base_path.exists() {
        files.push(base_path.to_path_buf());
    }
    for path in files {
        let text = fs::read_to_string(&path).map_err(|source| DriverAuditError::Io {
            path: path.clone(),
            source,
        })?;
        let stats = verify_chain_text(&text, expected_prev.as_deref())?;
        if stats.event_count == 0 {
            continue;
        }
        if overall.event_count == 0 {
            overall.first_ts_unix_micros = stats.first_ts_unix_micros;
        }
        overall.event_count = overall.event_count.saturating_add(stats.event_count);
        overall.last_ts_unix_micros = stats.last_ts_unix_micros;
        overall.last_sha256 = stats.last_sha256.clone();
        expected_prev = stats.last_sha256;
    }
    Ok(overall)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backpressure_driver::SubstrateHealth;
    use crate::{BackpressureState, ResourceMeasurements};
    use tempfile::tempdir;

    fn reading(captured_at: u128) -> DriverReading {
        DriverReading {
            captured_at_unix_micros: captured_at,
            measurements: ResourceMeasurements {
                blackwell_vram_util: 0.5,
                gpu3090_util: 0.2,
                cpu_psi: 0.1,
                mem_psi: 0.05,
                io_psi: 0.02,
                human_gate_queue_depth: 2,
            },
            state: BackpressureState {
                blackwell_vram_high: false,
                gpu3090_busy: false,
                cpu_pressure: false,
                ram_pressure: false,
                io_pressure: false,
                human_gate_queue_high: false,
            },
            substrate_health: SubstrateHealth::all_healthy(),
        }
    }

    // ---------------- emit_driver_reading ------------------------------

    #[test]
    fn emit_appends_one_entry_with_no_prev_sha() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let entry = emit_driver_reading(&path, &reading(1_000), None).unwrap();
        assert!(entry.prev_event_sha256.is_none());
        assert_eq!(entry.captured_at_unix_micros, 1_000);
        let body = fs::read_to_string(&path).unwrap();
        assert!(body.ends_with('\n'));
        assert_eq!(body.lines().count(), 1);
    }

    #[test]
    fn emit_chains_subsequent_entries() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let _ = emit_driver_reading(&path, &reading(1_000), None).unwrap();
        let second = emit_driver_reading(&path, &reading(2_000), None).unwrap();
        assert!(second.prev_event_sha256.is_some());
        // verify_chain confirms the chain holds.
        let stats = verify_chain(&path).unwrap();
        assert_eq!(stats.event_count, 2);
        assert_eq!(stats.first_ts_unix_micros, Some(1_000));
        assert_eq!(stats.last_ts_unix_micros, Some(2_000));
    }

    #[test]
    fn emit_creates_parent_dirs() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("nested/sub/audit.jsonl");
        let _ = emit_driver_reading(&path, &reading(1), None).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn emit_embeds_signer_kid_when_provided() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let entry = emit_driver_reading(&path, &reading(1), Some("kid-2026")).unwrap();
        assert_eq!(entry.signer_kid.as_deref(), Some("kid-2026"));
        let line = fs::read_to_string(&path).unwrap();
        assert!(line.contains("\"signer_kid\":\"kid-2026\""));
    }

    // ---------------- verify_chain -------------------------------------

    #[test]
    fn verify_chain_empty_file() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let stats = verify_chain(&path).unwrap();
        assert_eq!(stats, ChainStats::empty());
    }

    #[test]
    fn verify_chain_detects_break() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let _ = emit_driver_reading(&path, &reading(1), None).unwrap();
        let _ = emit_driver_reading(&path, &reading(2), None).unwrap();
        // Tamper: rewrite the file so entry 2 has a wrong prev hash.
        let body = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = body.lines().map(str::to_owned).collect();
        lines[1] = lines[1].replace(&extract_prev_sha(&lines[1]), "0000000000");
        fs::write(&path, lines.join("\n") + "\n").unwrap();
        let err = verify_chain(&path).unwrap_err();
        assert!(matches!(err, DriverAuditError::ChainBreak { line: 2, .. }));
    }

    fn extract_prev_sha(line: &str) -> String {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        v["prev_event_sha256"].as_str().unwrap().to_owned()
    }

    #[test]
    fn verify_chain_detects_genesis_with_prev_sha() {
        // First entry MUST have prev_event_sha256=null. Tamper to
        // simulate a foreign event being prepended.
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let _ = emit_driver_reading(&path, &reading(1), None).unwrap();
        let body = fs::read_to_string(&path).unwrap();
        let tampered = body.replace("\"prev_event_sha256\":null", "\"prev_event_sha256\":\"deadbeef\"");
        fs::write(&path, tampered).unwrap();
        let err = verify_chain(&path).unwrap_err();
        assert!(matches!(err, DriverAuditError::ChainBreak { line: 1, .. }));
    }

    #[test]
    fn verify_chain_detects_malformed_json() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        fs::write(&path, "{not json}\n").unwrap();
        let err = verify_chain(&path).unwrap_err();
        assert!(matches!(err, DriverAuditError::ChainBreak { line: 1, .. }));
    }

    // ---------------- rotate_audit_log ---------------------------------

    #[test]
    fn rotate_no_op_when_under_threshold() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let _ = emit_driver_reading(&path, &reading(1), None).unwrap();
        let rotated = rotate_audit_log(&path, 1_000_000, 3).unwrap();
        assert!(!rotated);
        assert!(path.exists());
        assert!(!generation_path(&path, 1).exists());
    }

    #[test]
    fn rotate_shifts_when_over_threshold() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        // Write enough to exceed a tiny threshold.
        fs::write(&path, "x".repeat(2048)).unwrap();
        let rotated = rotate_audit_log(&path, 1024, 3).unwrap();
        assert!(rotated);
        assert!(generation_path(&path, 1).exists());
        // Fresh empty file created at the canonical path.
        assert!(path.exists());
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
    }

    #[test]
    fn rotate_drops_oldest_generation() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        fs::write(&path, "current").unwrap();
        fs::write(generation_path(&path, 1), "gen1").unwrap();
        fs::write(generation_path(&path, 2), "gen2").unwrap();
        fs::write(generation_path(&path, 3), "gen3").unwrap();
        let rotated = rotate_audit_log(&path, 1, 3).unwrap();
        assert!(rotated);
        // After rotation: .3 was dropped, .2→.3, .1→.2, current→.1
        assert_eq!(fs::read_to_string(generation_path(&path, 1)).unwrap(), "current");
        assert_eq!(fs::read_to_string(generation_path(&path, 2)).unwrap(), "gen1");
        assert_eq!(fs::read_to_string(generation_path(&path, 3)).unwrap(), "gen2");
        // gen3 dropped (the .4 path never existed; check the previous
        // .3 contents are now "gen2" not "gen3").
    }

    #[test]
    fn rotate_no_op_on_missing_file() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("never-created.jsonl");
        let rotated = rotate_audit_log(&path, 1024, 3).unwrap();
        assert!(!rotated);
    }

    // ---------------- verify_chain_across_generations ------------------

    #[test]
    fn cross_generation_chain_continuous() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        // Emit 3 entries, rotate, emit 2 more — chain must remain
        // continuous across the rotation boundary.
        let _ = emit_driver_reading(&path, &reading(100), None).unwrap();
        let _ = emit_driver_reading(&path, &reading(200), None).unwrap();
        let _ = emit_driver_reading(&path, &reading(300), None).unwrap();
        let _ = rotate_audit_log(&path, 1, 3).unwrap(); // force rotation
        let _ = emit_driver_reading(&path, &reading(400), None).unwrap();
        let _ = emit_driver_reading(&path, &reading(500), None).unwrap();
        let stats = verify_chain_across_generations(&path, 3).unwrap();
        assert_eq!(stats.event_count, 5);
        assert_eq!(stats.first_ts_unix_micros, Some(100));
        assert_eq!(stats.last_ts_unix_micros, Some(500));
    }

    #[test]
    fn cross_generation_detects_break_across_rotation() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let _ = emit_driver_reading(&path, &reading(100), None).unwrap();
        let _ = rotate_audit_log(&path, 1, 3).unwrap();
        let _ = emit_driver_reading(&path, &reading(200), None).unwrap();
        // Tamper the post-rotation entry's prev_event_sha256.
        let body = fs::read_to_string(&path).unwrap();
        let tampered = body.replace(&extract_prev_sha(body.trim()), "0000000000");
        fs::write(&path, tampered).unwrap();
        let err = verify_chain_across_generations(&path, 3).unwrap_err();
        assert!(matches!(err, DriverAuditError::ChainBreak { .. }));
    }

    // ---------------- generation_path ----------------------------------

    #[test]
    fn generation_path_format() {
        let p = Path::new("/var/log/selfdef/scheduler.driver.audit.jsonl");
        assert_eq!(
            generation_path(p, 5),
            PathBuf::from("/var/log/selfdef/scheduler.driver.audit.jsonl.5")
        );
    }

    // ---------------- Constants ----------------------------------------

    #[test]
    fn defaults_match_doc_constants() {
        assert_eq!(
            DEFAULT_DRIVER_AUDIT_PATH,
            "/var/log/selfdef/scheduler.driver.audit.jsonl"
        );
        assert_eq!(DEFAULT_ROTATE_BYTES, 64 * 1024 * 1024);
        assert_eq!(DEFAULT_MAX_GENERATIONS, 10);
        assert_eq!(DRIVER_AUDIT_SCHEMA_VERSION, "1.0.0");
    }
}
