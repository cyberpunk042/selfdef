//! `selfdef-scheduler::human_gate` — M01158: Human-gate queue depth source
//! for the Goldilocks Scheduler backpressure surface.
//!
//! Dump grounding (avx-plus-plus 2026-05-18 line 18197):
//! > *"Linux PSI + DCGM + trace metrics feed the scheduler"*
//!
//! Catalog grounding: MS048 module `M01158 selfdef-scheduler-human-gate-
//! tracker` per `~/selfdef/backlog/milestones/MS048-goldilocks-
//! scheduler-hardware-aware-resource-routing.md` + R11349
//! (`human_gate_queue_high` threshold default 5 — already in
//! `BackpressureThresholds`).
//!
//! Doctrinal anchor: [Peace Machine + Core Law](https://github.com/
//! cyberpunk042/devops-solutions-information-hub/blob/main/wiki/spine/
//! doctrine/peace-machine-and-core-law.md) — Core Law clause
//! "Runtime routes" + peace-machine clause "sovereign enough that
//! intelligence remains in the user's hands" (operator must clear
//! the human-gate before the scheduler routes blocked work; high
//! queue depth = operator-attention-bottleneck → defer autonomy).
//!
//! ## What this module provides
//!
//! 1. `HumanGateReading` — aggregate snapshot: `total_pending` (the
//!    field consumed by `BackpressureThresholds.human_gate_queue_high`)
//!    + `per_source` breakdown for operator visibility.
//! 2. `HumanGateSource` trait — Effector-style stubbable boundary.
//! 3. `IpsPendingRestoresHumanGateSource` — real-substrate impl that
//!    reads `/var/lib/selfdef/*/pending-restores.json` (the 14 IPS-
//!    quattuordectet primitives' pending-restore queues), counts each
//!    JSON array length, sums the total. Honest-offline: missing
//!    state root returns `HumanGateError::Unavailable`.
//! 4. `MockHumanGateSource` — test injector.
//! 5. `HumanGateError` — typed errors (`Io` / `Parse` / `Unavailable`).
//!
//! ## Why IPS pending-restores
//!
//! Per the operator's "the 14 IPS axes (SDD-065..078) all expose
//! `pending-restores.json` files under
//! `/var/lib/selfdef/<primitive>/pending-restores.json`" — these
//! files ARE the human-gate substrate. Each entry is a
//! pending-operator-decision the scheduler should consider as
//! human-attention demand. Summing them gives the
//! `human_gate_queue_depth` field that the existing
//! `BackpressureMonitor` (R11349) already consumes.
//!
//! Future MS003-multi-sig-pending and MS028-inference-pending
//! queues can be folded in by adding more source contributors;
//! the trait is composable.
//!
//! ## Non-goals
//!
//! - Not an approval mechanism. This module READS pending counts;
//!   approval / rejection lives in the cockpit (sovereign-os
//!   `scripts/cockpit/*-queue.py`).
//! - Not a Prometheus exporter (M01168).
//! - Not a per-primitive routing layer; it surfaces aggregate only.
//!
//! Standing rule: We do not minimize anything.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default state root where `<primitive>/pending-restores.json`
/// files live.
pub const DEFAULT_STATE_ROOT: &str = "/var/lib/selfdef";

/// File-name suffix the IPS primitives use for their pending-decision
/// queues.
pub const PENDING_RESTORES_FILENAME: &str = "pending-restores.json";

// ============================================================================
// HumanGateReading
// ============================================================================

/// Aggregate human-gate queue depth at one instant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanGateReading {
    /// Wall-clock unix microseconds when the sample was taken.
    pub captured_at_unix_micros: u128,
    /// Sum of pending entries across all sources. Matches the
    /// `human_gate_queue_depth` field of [`crate::ResourceMeasurements`].
    pub total_pending: u32,
    /// Per-source breakdown for operator visibility + cockpit display.
    /// Each entry is `(source_name, count)`. Sorted alphabetically by
    /// `source_name` for deterministic output.
    pub per_source: Vec<(String, u32)>,
}

impl HumanGateReading {
    /// Construct an all-zero reading.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            captured_at_unix_micros: 0,
            total_pending: 0,
            per_source: Vec::new(),
        }
    }
}

// ============================================================================
// HumanGateError
// ============================================================================

/// Errors emitted by [`HumanGateSource`] implementations.
#[derive(Debug, Error)]
pub enum HumanGateError {
    /// Filesystem IO failed reading a queue file.
    #[error("human-gate io ({path}): {source}")]
    Io {
        /// Path that failed.
        path: PathBuf,
        /// Underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// A queue file was present but malformed JSON or wrong shape
    /// (not a top-level array).
    #[error("human-gate parse ({path}): {reason}")]
    Parse {
        /// Path that failed.
        path: PathBuf,
        /// Human reason.
        reason: String,
    },
    /// State root missing (selfdef not deployed yet, fresh host,
    /// container without state mount). Honest-offline marker.
    #[error("human-gate unavailable: {0}")]
    Unavailable(String),
}

// ============================================================================
// HumanGateSource trait
// ============================================================================

/// Effector-style stubbable boundary between the scheduler and the
/// human-gate substrate.
pub trait HumanGateSource: Send + Sync {
    /// Take a snapshot of all configured gate queues.
    ///
    /// # Errors
    ///
    /// `HumanGateError::Unavailable` if substrate absent;
    /// `HumanGateError::Io` on transient FS errors;
    /// `HumanGateError::Parse` on malformed queue files.
    fn read(&self) -> Result<HumanGateReading, HumanGateError>;
}

// ============================================================================
// IpsPendingRestoresHumanGateSource (real-substrate impl)
// ============================================================================

/// Real-substrate `HumanGateSource` reading
/// `<state-root>/<primitive>/pending-restores.json` for every
/// `<primitive>` subdirectory. Empty / missing files contribute 0;
/// malformed JSON contributes 0 + the error is propagated (operator
/// must see it).
///
/// Honest-offline: state root missing → Unavailable.
#[derive(Debug, Clone)]
pub struct IpsPendingRestoresHumanGateSource {
    state_root: PathBuf,
}

impl IpsPendingRestoresHumanGateSource {
    /// Construct against `/var/lib/selfdef`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state_root: PathBuf::from(DEFAULT_STATE_ROOT),
        }
    }

    /// Override the state root (test fixture trees).
    #[must_use]
    pub fn with_state_root(state_root: impl Into<PathBuf>) -> Self {
        Self {
            state_root: state_root.into(),
        }
    }

    /// Borrow the state root.
    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }
}

impl Default for IpsPendingRestoresHumanGateSource {
    fn default() -> Self {
        Self::new()
    }
}

impl HumanGateSource for IpsPendingRestoresHumanGateSource {
    fn read(&self) -> Result<HumanGateReading, HumanGateError> {
        if !self.state_root.is_dir() {
            return Err(HumanGateError::Unavailable(format!(
                "state root {} not present",
                self.state_root.display()
            )));
        }
        let mut per_source: Vec<(String, u32)> = Vec::new();
        let mut total_pending: u32 = 0;
        let entries = fs::read_dir(&self.state_root).map_err(|source| HumanGateError::Io {
            path: self.state_root.clone(),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| HumanGateError::Io {
                path: self.state_root.clone(),
                source,
            })?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let queue_path = path.join(PENDING_RESTORES_FILENAME);
            if !queue_path.is_file() {
                // Primitive present but no pending queue file yet
                // (fresh primitive that hasn't queued anything). Skip
                // silently — contributes 0.
                continue;
            }
            let count = count_json_array_entries(&queue_path)?;
            let source_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            per_source.push((source_name, count));
            total_pending = total_pending.saturating_add(count);
        }
        per_source.sort_by(|a, b| a.0.cmp(&b.0));
        let captured_at_unix_micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros())
            .unwrap_or(0);
        Ok(HumanGateReading {
            captured_at_unix_micros,
            total_pending,
            per_source,
        })
    }
}

fn count_json_array_entries(path: &Path) -> Result<u32, HumanGateError> {
    let bytes = fs::read(path).map_err(|source| HumanGateError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if bytes.is_empty() {
        return Ok(0);
    }
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| HumanGateError::Parse {
            path: path.to_path_buf(),
            reason: format!("invalid json: {e}"),
        })?;
    let arr = value.as_array().ok_or_else(|| HumanGateError::Parse {
        path: path.to_path_buf(),
        reason: format!("expected top-level array, got {value}"),
    })?;
    Ok(u32::try_from(arr.len()).unwrap_or(u32::MAX))
}

// ============================================================================
// MockHumanGateSource (test injector)
// ============================================================================

/// In-memory `HumanGateSource` for tests.
#[derive(Debug, Clone)]
pub struct MockHumanGateSource {
    total_pending: u32,
    per_source: Vec<(String, u32)>,
    fail_with: Option<MockFailureMode>,
}

#[derive(Debug, Clone, PartialEq)]
enum MockFailureMode {
    Unavailable,
}

impl MockHumanGateSource {
    /// All-clean source.
    #[must_use]
    pub fn clean() -> Self {
        Self {
            total_pending: 0,
            per_source: Vec::new(),
            fail_with: None,
        }
    }

    /// Set the total directly (per-source breakdown left empty).
    #[must_use]
    pub fn with_total(mut self, total: u32) -> Self {
        self.total_pending = total;
        self
    }

    /// Add a single named source to the per-source breakdown.
    /// `total_pending` is automatically incremented.
    #[must_use]
    pub fn with_source(mut self, name: impl Into<String>, count: u32) -> Self {
        self.per_source.push((name.into(), count));
        self.total_pending = self.total_pending.saturating_add(count);
        self.per_source.sort_by(|a, b| a.0.cmp(&b.0));
        self
    }

    /// Simulate honest-offline.
    #[must_use]
    pub fn unavailable() -> Self {
        Self {
            total_pending: 0,
            per_source: Vec::new(),
            fail_with: Some(MockFailureMode::Unavailable),
        }
    }
}

impl HumanGateSource for MockHumanGateSource {
    fn read(&self) -> Result<HumanGateReading, HumanGateError> {
        if let Some(MockFailureMode::Unavailable) = self.fail_with {
            return Err(HumanGateError::Unavailable("mock unavailable".to_string()));
        }
        Ok(HumanGateReading {
            captured_at_unix_micros: 0,
            total_pending: self.total_pending,
            per_source: self.per_source.clone(),
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_pending_queue(state_root: &Path, primitive: &str, entries: usize) {
        let dir = state_root.join(primitive);
        fs::create_dir_all(&dir).unwrap();
        let mut body = String::from("[");
        for i in 0..entries {
            if i > 0 {
                body.push(',');
            }
            body.push_str(&format!("{{\"id\":{i}}}"));
        }
        body.push(']');
        fs::write(dir.join(PENDING_RESTORES_FILENAME), body).unwrap();
    }

    // ---------------- IpsPendingRestoresHumanGateSource -------------------

    #[test]
    fn reads_single_primitive() {
        let tmp = tempdir().unwrap();
        write_pending_queue(tmp.path(), "blockset", 3);
        let src = IpsPendingRestoresHumanGateSource::with_state_root(tmp.path());
        let r = src.read().unwrap();
        assert_eq!(r.total_pending, 3);
        assert_eq!(r.per_source, vec![("blockset".to_string(), 3)]);
    }

    #[test]
    fn reads_multiple_primitives_sums() {
        let tmp = tempdir().unwrap();
        write_pending_queue(tmp.path(), "blockset", 2);
        write_pending_queue(tmp.path(), "quarantine", 5);
        write_pending_queue(tmp.path(), "capability-drops", 1);
        let src = IpsPendingRestoresHumanGateSource::with_state_root(tmp.path());
        let r = src.read().unwrap();
        assert_eq!(r.total_pending, 8);
        assert_eq!(r.per_source.len(), 3);
        // Sorted alphabetically.
        assert_eq!(r.per_source[0].0, "blockset");
        assert_eq!(r.per_source[1].0, "capability-drops");
        assert_eq!(r.per_source[2].0, "quarantine");
    }

    #[test]
    fn empty_queue_file_contributes_zero() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("env-scrubs");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(PENDING_RESTORES_FILENAME), "[]").unwrap();
        let src = IpsPendingRestoresHumanGateSource::with_state_root(tmp.path());
        let r = src.read().unwrap();
        assert_eq!(r.total_pending, 0);
        assert_eq!(r.per_source, vec![("env-scrubs".to_string(), 0)]);
    }

    #[test]
    fn truly_empty_file_returns_zero() {
        // Some primitives may write an empty file before populating;
        // we tolerate it (0 entries, no parse error).
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("netns-isolations");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(PENDING_RESTORES_FILENAME), "").unwrap();
        let src = IpsPendingRestoresHumanGateSource::with_state_root(tmp.path());
        let r = src.read().unwrap();
        assert_eq!(r.total_pending, 0);
    }

    #[test]
    fn missing_queue_file_skipped_silently() {
        // Primitive dir present but no pending-restores.json yet.
        let tmp = tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("mfa-grant-revocations")).unwrap();
        let src = IpsPendingRestoresHumanGateSource::with_state_root(tmp.path());
        let r = src.read().unwrap();
        assert_eq!(r.total_pending, 0);
        assert!(r.per_source.is_empty());
    }

    #[test]
    fn malformed_json_propagates_parse_error() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("token-revocations");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(PENDING_RESTORES_FILENAME), "{not an array}").unwrap();
        let src = IpsPendingRestoresHumanGateSource::with_state_root(tmp.path());
        let err = src.read().unwrap_err();
        let HumanGateError::Parse { path, reason } = err else {
            panic!("expected Parse, got {err:?}")
        };
        assert!(path.ends_with("token-revocations/pending-restores.json"));
        assert!(reason.contains("invalid json"));
    }

    #[test]
    fn non_array_top_level_rejected() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("revocations");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(PENDING_RESTORES_FILENAME), "{\"object\": true}").unwrap();
        let src = IpsPendingRestoresHumanGateSource::with_state_root(tmp.path());
        let err = src.read().unwrap_err();
        let HumanGateError::Parse { reason, .. } = err else {
            panic!("expected Parse")
        };
        assert!(reason.contains("top-level array"));
    }

    #[test]
    fn missing_state_root_returns_unavailable() {
        let tmp = tempdir().unwrap();
        let nonexistent = tmp.path().join("never-created");
        let src = IpsPendingRestoresHumanGateSource::with_state_root(&nonexistent);
        let err = src.read().unwrap_err();
        assert!(matches!(err, HumanGateError::Unavailable(_)));
    }

    #[test]
    fn non_directory_entries_ignored() {
        // Files at the state root that aren't primitive dirs are
        // ignored rather than failing.
        let tmp = tempdir().unwrap();
        fs::write(tmp.path().join("not-a-dir.txt"), "garbage").unwrap();
        write_pending_queue(tmp.path(), "blockset", 1);
        let src = IpsPendingRestoresHumanGateSource::with_state_root(tmp.path());
        let r = src.read().unwrap();
        assert_eq!(r.total_pending, 1);
    }

    #[test]
    fn ips_quattuordectet_simulation() {
        // Simulate the 14 IPS primitives all having pending queues
        // — the operator's IPS-host-overview "pending decisions
        // (sum across 14 queues)" panel shape.
        let tmp = tempdir().unwrap();
        let primitives = [
            "blockset",
            "quarantine",
            "revocations",
            "token-revocations",
            "mfa-grant-revocations",
            "netns-isolations",
            "mount-bindings",
            "process-tree-freezes",
            "socket-fd-revocations",
            "env-scrubs",
            "capability-drops",
            "kernel-keyring-evictions",
            "apparmor-profile-pivots",
            "bpf-map-element-clears",
        ];
        for (i, p) in primitives.iter().enumerate() {
            write_pending_queue(tmp.path(), p, i);
        }
        let src = IpsPendingRestoresHumanGateSource::with_state_root(tmp.path());
        let r = src.read().unwrap();
        // sum 0..14 = 14*13/2 = 91
        assert_eq!(r.total_pending, 91);
        assert_eq!(r.per_source.len(), 14);
    }

    // ---------------- MockHumanGateSource ---------------------------------

    #[test]
    fn mock_clean_zero() {
        let r = MockHumanGateSource::clean().read().unwrap();
        assert_eq!(r.total_pending, 0);
        assert!(r.per_source.is_empty());
    }

    #[test]
    fn mock_with_total() {
        let r = MockHumanGateSource::clean().with_total(7).read().unwrap();
        assert_eq!(r.total_pending, 7);
    }

    #[test]
    fn mock_with_source_increments_total_and_sorts() {
        let r = MockHumanGateSource::clean()
            .with_source("revocations", 2)
            .with_source("blockset", 5)
            .with_source("quarantine", 1)
            .read()
            .unwrap();
        assert_eq!(r.total_pending, 8);
        assert_eq!(r.per_source[0].0, "blockset");
        assert_eq!(r.per_source[1].0, "quarantine");
        assert_eq!(r.per_source[2].0, "revocations");
    }

    #[test]
    fn mock_unavailable() {
        let err = MockHumanGateSource::unavailable().read().unwrap_err();
        assert!(matches!(err, HumanGateError::Unavailable(_)));
    }

    // ---------------- Trait object dispatch -------------------------------

    #[test]
    fn trait_object_dispatch_works() {
        let sources: Vec<Box<dyn HumanGateSource>> = vec![
            Box::new(MockHumanGateSource::clean().with_total(3)),
            Box::new(MockHumanGateSource::unavailable()),
        ];
        let r1 = sources[0].read().unwrap();
        assert_eq!(r1.total_pending, 3);
        let err = sources[1].read().unwrap_err();
        assert!(matches!(err, HumanGateError::Unavailable(_)));
    }

    // ---------------- Constants -------------------------------------------

    #[test]
    fn constants_match_ops_convention() {
        assert_eq!(DEFAULT_STATE_ROOT, "/var/lib/selfdef");
        assert_eq!(PENDING_RESTORES_FILENAME, "pending-restores.json");
    }
}
