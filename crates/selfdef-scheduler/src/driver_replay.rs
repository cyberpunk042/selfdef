//! `selfdef-scheduler::driver_replay` — M01161: Counterfactual replay
//! of `DriverReading` audit entries against alternate `BackpressureThresholds`.
//!
//! Catalog grounding: MS048 module `M01161 selfdef-scheduler-replay-engine
//! (per R11393-R11398)` per `~/selfdef/backlog/milestones/MS048-goldilocks-
//! scheduler-hardware-aware-resource-routing.md`. Companion to the
//! existing `crate::replay` (which replays per-request `Decision`
//! records); this module replays per-poll `DriverReading` substrate
//! observations.
//!
//! Doctrinal anchor: [Peace Machine + Core Law](https://github.com/
//! cyberpunk042/devops-solutions-information-hub/blob/main/wiki/spine/
//! doctrine/peace-machine-and-core-law.md) — eight-axis choice surface
//! ("the user can choose at every stage"). M01161 surfaces the
//! counterfactual: *"if I'd set blackwell_vram_high=0.85 instead of
//! 0.90, would the BlackwellVramExhaustion alert have fired earlier?"*
//! The answer is computable from the M01170 audit log without re-
//! executing any production poll.
//!
//! ## What this module provides
//!
//! 1. `replay_driver_reading(reading, thresholds, prev_state)` — pure
//!    function: given one `DriverReading` and a `BackpressureThresholds`
//!    and a previous `BackpressureState` (for hysteresis), returns the
//!    `BackpressureState` that WOULD have been emitted under those thresholds.
//! 2. `replay_audit_log(path, alt_thresholds)` — walks the M01170
//!    audit log (current generation only), reconstructs the chain of
//!    DriverReadings, replays each against the alternate thresholds,
//!    returns `ReplayStats` summarizing the divergence. For
//!    cross-rotation walks see `replay_audit_log_across_generations`.
//! 3. `replay_audit_log_across_generations(base_path, alt_thresholds,
//!    max_gens)` — walks all rotated generations oldest→newest for
//!    a full historic replay.
//! 4. `ReplayStats` — { entries_replayed, per_surface_diffs,
//!    first_divergence_at_unix_micros, ... }. Operator surfaces in
//!    the future scheduler CLI + cockpit panel ("What-If" analysis).
//! 5. `SurfaceDiff` — per-surface count of (original-fired,
//!    counterfactual-fired) tuples + count of (only-original,
//!    only-counterfactual) divergences.
//!
//! ## Non-goals
//!
//! - Not a per-request decision replay (already shipped as
//!   `crate::replay`).
//! - Not a write-back. Pure read-only analysis.
//! - Not an alert simulator. Computes the per-poll state booleans
//!   that ALERT RULES would have evaluated against; the alert
//!   firing rules themselves (e.g. `for: 5m`) are external.
//!
//! Standing rule: We do not minimize anything.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::backpressure_driver::DriverReading;
use crate::decision_audit::DriverAuditEntry;
use crate::decision_audit::DEFAULT_MAX_GENERATIONS;
use crate::{
    BackpressureMonitor, BackpressureState, BackpressureThresholds, DriverAuditError,
};

/// Replay error — alias of [`crate::DriverAuditError`] (the replay engine
/// reads the same audit chain). Public so the `Returns [ReplayError]` doc
/// links on the public replay functions resolve.
pub type ReplayError = DriverAuditError;

// Re-export the alias the decision_audit module exports so callers
// have one error type.
pub use crate::decision_audit::DriverAuditError as M01161Error;
// `M01161Error` is just a re-export so the public re-export is
// stable even if `crate::decision_audit::DriverAuditError` is later
// renamed.
const _: fn(&crate::decision_audit::DriverAuditError) -> &M01161Error = |e| e;

// ============================================================================
// SurfaceDiff + ReplayStats
// ============================================================================

/// Per-backpressure-surface divergence counts between the original
/// (live thresholds) and the counterfactual (alternate thresholds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SurfaceDiff {
    /// Number of entries where BOTH original and counterfactual
    /// fired the surface.
    pub both_fired: u32,
    /// Number of entries where the counterfactual fired but the
    /// original did not (alternate threshold is stricter).
    pub only_counterfactual_fired: u32,
    /// Number of entries where the original fired but the
    /// counterfactual did not (alternate threshold is looser).
    pub only_original_fired: u32,
    /// Number of entries where neither fired.
    pub neither_fired: u32,
}

impl SurfaceDiff {
    fn observe(&mut self, original: bool, counterfactual: bool) {
        match (original, counterfactual) {
            (true, true) => self.both_fired += 1,
            (false, true) => self.only_counterfactual_fired += 1,
            (true, false) => self.only_original_fired += 1,
            (false, false) => self.neither_fired += 1,
        }
    }

    /// `true` iff the alternate threshold would have produced ANY
    /// different per-entry outcome.
    #[must_use]
    pub const fn diverges(&self) -> bool {
        self.only_counterfactual_fired > 0 || self.only_original_fired > 0
    }
}

/// Aggregated replay statistics for a sequence of `DriverReading`
/// entries.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ReplayStats {
    /// Number of entries walked.
    pub entries_replayed: u32,
    /// Per-surface divergence breakdown.
    pub cpu_pressure: SurfaceDiff,
    /// Per-surface divergence breakdown (memory PSI).
    pub ram_pressure: SurfaceDiff,
    /// Per-surface divergence breakdown (IO PSI).
    pub io_pressure: SurfaceDiff,
    /// Per-surface divergence breakdown (Blackwell VRAM).
    pub blackwell_vram_high: SurfaceDiff,
    /// Per-surface divergence breakdown (3090 utilization).
    pub gpu3090_busy: SurfaceDiff,
    /// Per-surface divergence breakdown (human-gate count).
    pub human_gate_queue_high: SurfaceDiff,
    /// Wall-clock unix microseconds of the FIRST entry whose
    /// counterfactual outcome diverged from the original (any
    /// surface). `None` if no divergence anywhere.
    pub first_divergence_at_unix_micros: Option<u128>,
}

impl ReplayStats {
    /// `true` iff at least one surface produced any divergent
    /// entry. The operator sees this as a single summary toggle
    /// in the "What-If" cockpit panel.
    #[must_use]
    pub const fn diverges(&self) -> bool {
        self.cpu_pressure.diverges()
            || self.ram_pressure.diverges()
            || self.io_pressure.diverges()
            || self.blackwell_vram_high.diverges()
            || self.gpu3090_busy.diverges()
            || self.human_gate_queue_high.diverges()
    }
}

// ============================================================================
// replay_driver_reading
// ============================================================================

/// Replay a single `DriverReading` against `thresholds`, with
/// hysteresis applied via `prev_state`. Pure function.
///
/// Identical to `BackpressureMonitor::update`'s state-transition
/// algorithm; isolated as a free function so the replay engine can
/// drive it across historic entries without mutating a live monitor.
#[must_use]
pub fn replay_driver_reading(
    reading: &DriverReading,
    thresholds: &BackpressureThresholds,
    prev_state: BackpressureState,
) -> BackpressureState {
    let monitor = BackpressureMonitor::with_thresholds(*thresholds);
    // BackpressureMonitor::with_thresholds initializes last_state to
    // BackpressureState::clean() — we need to thread the provided
    // prev_state. Pre-call update with the prev measurements would
    // require fabricating data; instead, simply call update once on
    // a freshly-constructed monitor where we've already initialized
    // last_state.
    //
    // Since BackpressureMonitor doesn't expose a constructor for
    // (thresholds + initial_state), we approximate by calling update
    // twice: first with the original-state-recreated measurements
    // (NOT meaningful) then with the real ones. To avoid this hack
    // we instead replicate the algorithm directly here — it's just
    // a few enter_or_stay calls and identical to the monitor's
    // update body.

    let _ = monitor; // silence unused if the simpler path is taken below
    let m = &reading.measurements;
    let t = thresholds;
    let h = BackpressureThresholds::HYSTERESIS_MARGIN;
    BackpressureState {
        blackwell_vram_high: enter_or_stay(
            prev_state.blackwell_vram_high,
            m.blackwell_vram_util,
            t.blackwell_vram_high,
            h,
        ),
        gpu3090_busy: enter_or_stay(prev_state.gpu3090_busy, m.gpu3090_util, t.gpu3090_busy, h),
        cpu_pressure: enter_or_stay(prev_state.cpu_pressure, m.cpu_psi, t.cpu_pressure, h),
        ram_pressure: enter_or_stay(prev_state.ram_pressure, m.mem_psi, t.ram_pressure, h),
        io_pressure: enter_or_stay(prev_state.io_pressure, m.io_psi, t.io_pressure, h),
        human_gate_queue_high: m.human_gate_queue_depth > t.human_gate_queue_high,
    }
}

#[inline]
const fn enter_or_stay(prev: bool, value: f32, threshold: f32, margin: f32) -> bool {
    if prev {
        // Stay pressured until value drops below (threshold - margin).
        value >= threshold - margin
    } else {
        // Enter pressure when value crosses threshold upward.
        value > threshold
    }
}

// ============================================================================
// replay_audit_log
// ============================================================================

/// Walk `audit_log`, replay every entry against `alt_thresholds`,
/// return `ReplayStats`.
///
/// # Errors
///
/// Returns [`ReplayError::Io`] on read failure;
/// [`ReplayError::ChainBreak`] on malformed entry.
pub fn replay_audit_log(
    audit_log: &Path,
    alt_thresholds: &BackpressureThresholds,
) -> Result<ReplayStats, ReplayError> {
    if !audit_log.exists() {
        return Ok(ReplayStats::default());
    }
    let text = fs::read_to_string(audit_log).map_err(|source| ReplayError::Io {
        path: audit_log.to_path_buf(),
        source,
    })?;
    replay_text(&text, alt_thresholds, BackpressureState::clean())
}

/// Walk `base_path.N` → ... → `base_path.1` → `base_path`, replay
/// every entry. Hysteresis state THREADS across generation
/// boundaries.
///
/// # Errors
///
/// Returns [`ReplayError`] as `replay_audit_log` does.
pub fn replay_audit_log_across_generations(
    base_path: &Path,
    alt_thresholds: &BackpressureThresholds,
    max_generations: u32,
) -> Result<ReplayStats, ReplayError> {
    let mut stats = ReplayStats::default();
    let mut prev_state = BackpressureState::clean();
    let mut files: Vec<std::path::PathBuf> = Vec::new();
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
        let text = fs::read_to_string(&path).map_err(|source| ReplayError::Io {
            path: path.clone(),
            source,
        })?;
        let (chunk_stats, end_state) = replay_text_keep_state(&text, alt_thresholds, prev_state)?;
        merge(&mut stats, &chunk_stats);
        prev_state = end_state;
    }
    Ok(stats)
}

fn merge(into: &mut ReplayStats, from: &ReplayStats) {
    into.entries_replayed += from.entries_replayed;
    merge_surface(&mut into.cpu_pressure, &from.cpu_pressure);
    merge_surface(&mut into.ram_pressure, &from.ram_pressure);
    merge_surface(&mut into.io_pressure, &from.io_pressure);
    merge_surface(&mut into.blackwell_vram_high, &from.blackwell_vram_high);
    merge_surface(&mut into.gpu3090_busy, &from.gpu3090_busy);
    merge_surface(&mut into.human_gate_queue_high, &from.human_gate_queue_high);
    if into.first_divergence_at_unix_micros.is_none() {
        into.first_divergence_at_unix_micros = from.first_divergence_at_unix_micros;
    }
}

fn merge_surface(into: &mut SurfaceDiff, from: &SurfaceDiff) {
    into.both_fired += from.both_fired;
    into.only_counterfactual_fired += from.only_counterfactual_fired;
    into.only_original_fired += from.only_original_fired;
    into.neither_fired += from.neither_fired;
}

fn replay_text(
    text: &str,
    alt: &BackpressureThresholds,
    init_state: BackpressureState,
) -> Result<ReplayStats, ReplayError> {
    let (stats, _end) = replay_text_keep_state(text, alt, init_state)?;
    Ok(stats)
}

fn replay_text_keep_state(
    text: &str,
    alt: &BackpressureThresholds,
    init_state: BackpressureState,
) -> Result<(ReplayStats, BackpressureState), ReplayError> {
    let mut stats = ReplayStats::default();
    let mut prev_counterfactual_state = init_state;
    for (idx, raw_line) in text.lines().enumerate() {
        let line_no = idx + 1;
        if raw_line.trim().is_empty() {
            continue;
        }
        let entry: DriverAuditEntry =
            serde_json::from_str(raw_line).map_err(|e| ReplayError::ChainBreak {
                line: line_no,
                detail: format!("malformed json: {e}"),
            })?;
        // The original-state at the time of the entry is what the
        // entry itself recorded.
        let original_state = entry.reading.state;
        let counterfactual_state =
            replay_driver_reading(&entry.reading, alt, prev_counterfactual_state);
        stats
            .cpu_pressure
            .observe(original_state.cpu_pressure, counterfactual_state.cpu_pressure);
        stats
            .ram_pressure
            .observe(original_state.ram_pressure, counterfactual_state.ram_pressure);
        stats
            .io_pressure
            .observe(original_state.io_pressure, counterfactual_state.io_pressure);
        stats.blackwell_vram_high.observe(
            original_state.blackwell_vram_high,
            counterfactual_state.blackwell_vram_high,
        );
        stats
            .gpu3090_busy
            .observe(original_state.gpu3090_busy, counterfactual_state.gpu3090_busy);
        stats.human_gate_queue_high.observe(
            original_state.human_gate_queue_high,
            counterfactual_state.human_gate_queue_high,
        );
        if stats.first_divergence_at_unix_micros.is_none()
            && state_diverges(&original_state, &counterfactual_state)
        {
            stats.first_divergence_at_unix_micros = Some(entry.reading.captured_at_unix_micros);
        }
        stats.entries_replayed += 1;
        prev_counterfactual_state = counterfactual_state;
    }
    Ok((stats, prev_counterfactual_state))
}

fn state_diverges(a: &BackpressureState, b: &BackpressureState) -> bool {
    a.cpu_pressure != b.cpu_pressure
        || a.ram_pressure != b.ram_pressure
        || a.io_pressure != b.io_pressure
        || a.blackwell_vram_high != b.blackwell_vram_high
        || a.gpu3090_busy != b.gpu3090_busy
        || a.human_gate_queue_high != b.human_gate_queue_high
}

fn generation_path(base: &Path, n: u32) -> std::path::PathBuf {
    let mut s = base.as_os_str().to_owned();
    s.push(format!(".{n}"));
    std::path::PathBuf::from(s)
}

#[allow(unused)]
const _DEFAULT_MAX_GENERATIONS_LINK: u32 = DEFAULT_MAX_GENERATIONS;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backpressure_driver::SubstrateHealth;
    use crate::decision_audit::{
        emit_driver_reading, rotate_audit_log, DEFAULT_MAX_GENERATIONS as MAX_GENS,
    };
    use crate::ResourceMeasurements;
    use tempfile::tempdir;

    fn reading_with(ts: u128, cpu: f32, blackwell: f32) -> DriverReading {
        DriverReading {
            captured_at_unix_micros: ts,
            measurements: ResourceMeasurements {
                blackwell_vram_util: blackwell,
                gpu3090_util: 0.0,
                cpu_psi: cpu,
                mem_psi: 0.0,
                io_psi: 0.0,
                human_gate_queue_depth: 0,
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

    fn baseline_thresholds() -> BackpressureThresholds {
        BackpressureThresholds::default_for_sain01()
    }

    // ---------------- replay_driver_reading ---------------------------

    #[test]
    fn replay_pure_below_threshold_no_pressure() {
        let r = reading_with(1, 0.10, 0.20);
        let s = replay_driver_reading(&r, &baseline_thresholds(), BackpressureState::clean());
        assert!(!s.cpu_pressure);
        assert!(!s.blackwell_vram_high);
    }

    #[test]
    fn replay_pure_above_threshold_enters_pressure() {
        let r = reading_with(1, 0.60, 0.95);
        let s = replay_driver_reading(&r, &baseline_thresholds(), BackpressureState::clean());
        assert!(s.cpu_pressure, "0.60 > 0.50 should enter cpu_pressure");
        assert!(
            s.blackwell_vram_high,
            "0.95 > 0.90 should enter blackwell_vram_high"
        );
    }

    #[test]
    fn replay_honors_hysteresis_in_band_stays_pressured() {
        // Enter cpu pressure first.
        let high = reading_with(1, 0.55, 0.0);
        let s1 = replay_driver_reading(&high, &baseline_thresholds(), BackpressureState::clean());
        assert!(s1.cpu_pressure);
        // 0.42 is in the hysteresis band (0.50 - 0.10 = 0.40 < 0.42 < 0.50);
        // should stay pressured.
        let in_band = reading_with(2, 0.42, 0.0);
        let s2 = replay_driver_reading(&in_band, &baseline_thresholds(), s1);
        assert!(s2.cpu_pressure, "0.42 in hysteresis band should stay pressured");
    }

    #[test]
    fn replay_lower_threshold_fires_where_original_did_not() {
        let r = reading_with(1, 0.0, 0.85);
        let baseline = baseline_thresholds();
        // Under default 0.90 — no fire.
        let s_baseline = replay_driver_reading(&r, &baseline, BackpressureState::clean());
        assert!(!s_baseline.blackwell_vram_high);
        // Under 0.80 alternate — fires.
        let mut alt = baseline;
        alt.blackwell_vram_high = 0.80;
        let s_alt = replay_driver_reading(&r, &alt, BackpressureState::clean());
        assert!(s_alt.blackwell_vram_high);
    }

    // ---------------- replay_audit_log ----------------------------------

    #[test]
    fn replay_empty_log_yields_default_stats() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let stats = replay_audit_log(&path, &baseline_thresholds()).unwrap();
        assert_eq!(stats, ReplayStats::default());
    }

    #[test]
    fn replay_against_same_thresholds_no_divergence() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        // Note: emitted entries have state=clean() so the "original"
        // state per-entry is always clean, regardless of the
        // measurements. Pick readings below threshold so counterfactual
        // is also clean, and divergence is 0.
        emit_driver_reading(&path, &reading_with(100, 0.10, 0.20), None).unwrap();
        emit_driver_reading(&path, &reading_with(200, 0.15, 0.30), None).unwrap();
        let stats = replay_audit_log(&path, &baseline_thresholds()).unwrap();
        assert_eq!(stats.entries_replayed, 2);
        assert!(!stats.diverges());
        assert!(stats.first_divergence_at_unix_micros.is_none());
    }

    #[test]
    fn replay_lower_threshold_diverges_at_first_high_entry() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        emit_driver_reading(&path, &reading_with(100, 0.0, 0.20), None).unwrap();
        emit_driver_reading(&path, &reading_with(200, 0.0, 0.50), None).unwrap();
        emit_driver_reading(&path, &reading_with(300, 0.0, 0.85), None).unwrap();
        emit_driver_reading(&path, &reading_with(400, 0.0, 0.95), None).unwrap();

        let mut alt = baseline_thresholds();
        alt.blackwell_vram_high = 0.80;
        let stats = replay_audit_log(&path, &alt).unwrap();
        assert_eq!(stats.entries_replayed, 4);
        assert!(stats.diverges());
        // First divergence at ts=300 (0.85 > 0.80 alt-threshold;
        // original 0.90 not crossed).
        assert_eq!(stats.first_divergence_at_unix_micros, Some(300));
        assert_eq!(stats.blackwell_vram_high.only_counterfactual_fired, 2);
        // The 0.95 entry: alt-counterfactual fires; original-recorded-state
        // is still clean (because emit_driver_reading writes whatever
        // state the LIVE monitor produced — which here is the test
        // fixture's clean state). Both stats.both_fired and
        // only_original_fired stay 0.
        assert_eq!(stats.blackwell_vram_high.only_original_fired, 0);
    }

    #[test]
    fn replay_higher_threshold_only_original_fires_when_state_says_so() {
        // In this test we manually inject readings with state.blackwell_vram_high=true
        // (as if the live monitor had recorded it) and replay against a higher
        // threshold that would NOT fire. We use serde to construct the entry
        // shape directly so we can set the inner state without invoking the
        // live monitor.
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let mut r = reading_with(100, 0.0, 0.85);
        r.state.blackwell_vram_high = true; // pretend the live monitor recorded this
        let entry = DriverAuditEntry {
            schema_version: "1.0.0".to_string(),
            captured_at_unix_micros: r.captured_at_unix_micros,
            reading: r,
            signer_kid: None,
            prev_event_sha256: None,
        };
        let body = format!("{}\n", serde_json::to_string(&entry).unwrap());
        fs::write(&path, body).unwrap();

        // Original threshold 0.90 wouldn't have fired against 0.85 either,
        // but the recorded state says fired=true. Alt threshold 0.95 wouldn't
        // fire either. So only_original_fired should count 1.
        let mut alt = baseline_thresholds();
        alt.blackwell_vram_high = 0.95;
        let stats = replay_audit_log(&path, &alt).unwrap();
        assert_eq!(stats.entries_replayed, 1);
        assert_eq!(stats.blackwell_vram_high.only_original_fired, 1);
        assert_eq!(stats.blackwell_vram_high.only_counterfactual_fired, 0);
        assert!(stats.diverges());
    }

    #[test]
    fn replay_malformed_json_propagates() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        fs::write(&path, "{not json}\n").unwrap();
        let err = replay_audit_log(&path, &baseline_thresholds()).unwrap_err();
        assert!(matches!(err, ReplayError::ChainBreak { line: 1, .. }));
    }

    // ---------------- replay_audit_log_across_generations -------------

    #[test]
    fn replay_across_generations_threads_state() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        emit_driver_reading(&path, &reading_with(100, 0.0, 0.50), None).unwrap();
        emit_driver_reading(&path, &reading_with(200, 0.0, 0.85), None).unwrap();
        rotate_audit_log(&path, 1, MAX_GENS).unwrap();
        emit_driver_reading(&path, &reading_with(300, 0.0, 0.95), None).unwrap();

        let mut alt = baseline_thresholds();
        alt.blackwell_vram_high = 0.80;

        let stats = replay_audit_log_across_generations(&path, &alt, MAX_GENS).unwrap();
        assert_eq!(stats.entries_replayed, 3);
        assert!(stats.diverges());
        // 0.85 is the first entry where alt counterfactual fires.
        assert_eq!(stats.first_divergence_at_unix_micros, Some(200));
    }

    #[test]
    fn replay_across_generations_no_files_returns_default() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let stats = replay_audit_log_across_generations(&path, &baseline_thresholds(), 3).unwrap();
        assert_eq!(stats, ReplayStats::default());
    }

    // ---------------- SurfaceDiff / ReplayStats predicates -------------

    #[test]
    fn surface_diff_diverges_only_when_divergent_outcomes() {
        let mut sd = SurfaceDiff {
            both_fired: 5,
            neither_fired: 5,
            ..SurfaceDiff::default()
        };
        assert!(!sd.diverges());
        sd.only_counterfactual_fired = 1;
        assert!(sd.diverges());
    }

    #[test]
    fn replay_stats_diverges_aggregates_per_surface() {
        let s = ReplayStats {
            cpu_pressure: SurfaceDiff {
                only_original_fired: 1,
                ..SurfaceDiff::default()
            },
            ..ReplayStats::default()
        };
        assert!(s.diverges());
    }
}
