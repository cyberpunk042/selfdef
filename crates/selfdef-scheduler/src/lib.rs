//! `selfdef-scheduler` — SDD-031 Deliverable 2: Goldilocks Scheduler
//! runtime (avx-plus-plus dump tail lines 18000-18250 IPS-side
//! implementation).
//!
//! Provides:
//! - [`ProfileRules`] — verbatim sain-01 §10 + dump 18000-18100 per-profile
//!   rule registry (the same request schedules differently under different
//!   profiles per R11254)
//! - [`AxisWeights`] — per-profile 7-axis weight matrix per R11291-R11332
//! - [`evaluate_objective`] — 7-axis objective function (latency + cost +
//!   risk + energy + human_attention + hardware_pressure + compound)
//! - [`BackpressureMonitor`] — 5 surfaces + thresholds + hysteresis +
//!   per-surface response policy per R11333-R11362
//! - [`Scheduler`] — top-level orchestrator: ingests request signals,
//!   evaluates objective under active profile + backpressure, emits a
//!   [`Decision`], appends to audit chain
//! - [`emit_audit_entry`] — atomic append to ZFS audit log + SHA-256 chain
//! - [`audit_chain_check`] — chain integrity verifier
//! - [`replay`] — counterfactual replay against alternate profile per
//!   R11393-R11398
//! - [`PsiSource`] / [`DcgmSource`] / [`HumanGateSource`] — Effector-style
//!   traits stubbable for testing (real-source bridges land in D7+)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod backpressure_driver;
pub mod backpressure_response;
pub mod config;
pub mod decide;
pub mod dcgm;
pub mod decision_audit;
pub mod driver_replay;
pub mod http_api;
pub mod human_gate;
pub mod kv_context_scheduling;
pub mod memory_scheduling;
pub mod objective_signals;
pub mod ocsf_emitter;
pub mod policy_signer;
pub mod prometheus_exporter;
pub mod psi;
pub mod scenarios;
pub mod scheduling_law;
pub mod tool_scheduling;
pub mod tui_panel;

pub use decision_audit::DriverAuditError;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use selfdef_scheduler_mirror::{
    AxisScores, BackpressureState, Decision, Profile, Route, SCHEMA_VERSION,
    SchedulerError as MirrorError,
};

/// Default ZFS audit log path (`tank/vault/context/scheduler_audit.log`
/// mounted at `/mnt/vault/context/scheduler_audit.log`).
pub const DEFAULT_AUDIT_LOG_PATH: &str = "/mnt/vault/context/scheduler_audit.log";

/// Default OCSF JSONL log (parallel to audit log for OCSF schema consumers).
pub const DEFAULT_OCSF_PATH: &str = "/var/log/selfdef/scheduler.ocsf.jsonl";

/// Default ring buffer directory (selfdef-cli + cockpit panel consumer).
pub const DEFAULT_RING_DIR: &str = "/var/cache/selfdef/scheduler/ring";

/// Default scheduler.toml location.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/selfdef/scheduler.toml";

/// OCSF schema version for emitted events.
pub const OCSF_SCHEMA_VERSION: &str = "1.1.0";

// ============================================================================
// Per-profile rule registry (R11248-R11254, dump 18011-18040 verbatim)
// ============================================================================

/// Per-profile scheduling rule tuples encoded verbatim from the dump.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileRules {
    /// Which profile this rule set is for.
    pub profile: Profile,
    /// Whether the profile favors latency over correctness (fast / production).
    pub favor_latency: bool,
    /// Whether the profile mandates oracle verification (careful).
    pub oracle_verification_required: bool,
    /// Whether the profile mandates tests-pass (careful / production).
    pub tests_required: bool,
    /// Whether the profile prefers scout-first routing (fast).
    pub scout_first: bool,
    /// Whether cloud routes are disabled (private).
    pub cloud_disabled: bool,
    /// Whether memory exposure is strict (private).
    pub strict_memory_exposure: bool,
    /// Whether the profile requires sandbox-first execution (autonomous / experimental).
    pub sandbox_first: bool,
    /// Whether the profile mandates frequent checkpointing (autonomous).
    pub checkpoint_often: bool,
    /// Whether the profile batches approvals (autonomous — lower human-gate burst).
    pub batch_approvals: bool,
    /// Whether the profile uses wide branch search (experimental).
    pub wide_branch_search: bool,
    /// Whether the profile disallows host commit (experimental).
    pub no_host_commit: bool,
    /// Whether the profile enforces strict commit gates (production).
    pub strict_commit_gates: bool,
    /// Whether the profile requires low variance (production).
    pub low_variance: bool,
    /// Whether the profile mandates strong observability (production).
    pub strong_observability: bool,
}

impl ProfileRules {
    /// Lookup the verbatim rule set for a profile per dump 18011-18040.
    #[must_use]
    pub const fn for_profile(profile: Profile) -> Self {
        match profile {
            // dump 18011-18014 (R11248)
            Profile::Fast => Self {
                profile,
                favor_latency: true,
                oracle_verification_required: false,
                tests_required: false,
                scout_first: true,
                cloud_disabled: false,
                strict_memory_exposure: false,
                sandbox_first: false,
                checkpoint_often: false,
                batch_approvals: false,
                wide_branch_search: false,
                no_host_commit: false,
                strict_commit_gates: false,
                low_variance: false,
                strong_observability: false,
            },
            // dump 18016-18019 (R11249)
            Profile::Careful => Self {
                profile,
                favor_latency: false,
                oracle_verification_required: true,
                tests_required: true,
                scout_first: false,
                cloud_disabled: false,
                strict_memory_exposure: false,
                sandbox_first: false,
                checkpoint_often: false,
                batch_approvals: false,
                wide_branch_search: false,
                no_host_commit: false,
                strict_commit_gates: false,
                low_variance: false,
                strong_observability: false,
            },
            // dump 18021-18024 (R11250)
            Profile::Private => Self {
                profile,
                favor_latency: false,
                oracle_verification_required: false,
                tests_required: false,
                scout_first: false,
                cloud_disabled: true,
                strict_memory_exposure: true,
                sandbox_first: false,
                checkpoint_often: false,
                batch_approvals: false,
                wide_branch_search: false,
                no_host_commit: false,
                strict_commit_gates: false,
                low_variance: false,
                strong_observability: false,
            },
            // dump 18026-18030 (R11251)
            Profile::Autonomous => Self {
                profile,
                favor_latency: false,
                oracle_verification_required: false,
                tests_required: false,
                scout_first: false,
                cloud_disabled: false,
                strict_memory_exposure: false,
                sandbox_first: true,
                checkpoint_often: true,
                batch_approvals: true,
                wide_branch_search: false,
                no_host_commit: false,
                strict_commit_gates: false,
                low_variance: false,
                strong_observability: false,
            },
            // dump 18032-18035 (R11252)
            Profile::Experimental => Self {
                profile,
                favor_latency: false,
                oracle_verification_required: false,
                tests_required: false,
                scout_first: false,
                cloud_disabled: false,
                strict_memory_exposure: false,
                sandbox_first: true,
                checkpoint_often: false,
                batch_approvals: false,
                wide_branch_search: true,
                no_host_commit: true,
                strict_commit_gates: false,
                low_variance: false,
                strong_observability: false,
            },
            // dump 18037-18040 (R11253)
            Profile::Production => Self {
                profile,
                favor_latency: true,
                oracle_verification_required: false,
                tests_required: true,
                scout_first: false,
                cloud_disabled: false,
                strict_memory_exposure: false,
                sandbox_first: false,
                checkpoint_often: false,
                batch_approvals: false,
                wide_branch_search: false,
                no_host_commit: false,
                strict_commit_gates: true,
                low_variance: true,
                strong_observability: true,
            },
        }
    }
}

// ============================================================================
// Per-profile 7-axis weight matrix (R11291-R11332)
// ============================================================================

/// Per-profile weight matrix. Each weight is in [0.0, 1.0]; higher
/// weight means the scheduler cares more about that axis under that
/// profile (so a high-weight axis penalty pulls compound score down
/// faster). See MS048 R11291-R11332.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct AxisWeights {
    /// Latency weight.
    pub latency: f32,
    /// Cost weight.
    pub cost: f32,
    /// Risk weight.
    pub risk: f32,
    /// Energy weight.
    pub energy: f32,
    /// Human-attention weight.
    pub human_attention: f32,
    /// Hardware-pressure weight.
    pub hardware_pressure: f32,
}

impl AxisWeights {
    /// Verbatim per-profile weights per R11291-R11326.
    #[must_use]
    pub const fn for_profile(profile: Profile) -> Self {
        match profile {
            // R11291-R11296
            Profile::Fast => Self {
                latency: 1.0,
                cost: 0.3,
                risk: 0.3,
                energy: 0.2,
                human_attention: 0.2,
                hardware_pressure: 0.5,
            },
            // R11297-R11302
            Profile::Careful => Self {
                latency: 0.5,
                cost: 0.5,
                risk: 1.0,
                energy: 0.5,
                human_attention: 0.9,
                hardware_pressure: 0.9,
            },
            // R11303-R11308 (cost is "irrelevant" — encoded as 0.0
            // because cloud is disabled in private profile)
            Profile::Private => Self {
                latency: 0.5,
                cost: 0.0,
                risk: 1.0,
                energy: 0.3,
                human_attention: 0.5,
                hardware_pressure: 0.5,
            },
            // R11309-R11314
            Profile::Autonomous => Self {
                latency: 0.5,
                cost: 0.5,
                risk: 0.7,
                energy: 0.5,
                // R11313 — low because batching approvals reduces operator burden
                human_attention: 0.2,
                hardware_pressure: 0.5,
            },
            // R11315-R11320
            Profile::Experimental => Self {
                latency: 0.5,
                cost: 0.3,
                risk: 0.3,
                energy: 0.3,
                human_attention: 0.3,
                hardware_pressure: 0.3,
            },
            // R11321-R11326
            Profile::Production => Self {
                latency: 0.9,
                cost: 0.7,
                risk: 1.0,
                energy: 0.5,
                human_attention: 0.5,
                hardware_pressure: 0.7,
            },
        }
    }

    /// Sum of all six axis weights (for normalization).
    #[must_use]
    pub fn sum(&self) -> f32 {
        self.latency
            + self.cost
            + self.risk
            + self.energy
            + self.human_attention
            + self.hardware_pressure
    }
}

// ============================================================================
// 7-axis objective evaluator (R11284-R11290 + R11329-R11330)
// ============================================================================

/// 7-axis raw signal inputs the scheduler computes from the request
/// and the environment before scoring. Each signal is in `[0.0, 1.0]`
/// where 1.0 = ideal (low latency / low cost / etc).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct AxisSignals {
    /// Estimated latency score for this routing decision (1.0 = fast).
    pub latency: f32,
    /// Estimated cost score (1.0 = cheap; 0.0 for private profile = irrelevant).
    pub cost: f32,
    /// Risk score (1.0 = low risk).
    pub risk: f32,
    /// Energy score (1.0 = low energy).
    pub energy: f32,
    /// Human-attention burden (1.0 = no operator decision needed).
    pub human_attention: f32,
    /// Hardware-pressure score (1.0 = no surfaces under pressure).
    pub hardware_pressure: f32,
}

/// Evaluate the 7-axis objective. Returns an [`AxisScores`] struct with
/// the per-axis values + the per-profile-weighted compound score per
/// R11329-R11330.
///
/// The compound score is the weighted average:
///
/// ```text
///   compound = Σ (signal_i * weight_i) / Σ (weight_i)
/// ```
///
/// This puts compound in [0.0, 1.0] when all signals + weights are in
/// [0.0, 1.0] (the validator on Decision::validate() enforces this).
#[must_use]
pub fn evaluate_objective(signals: AxisSignals, profile: Profile) -> AxisScores {
    let w = AxisWeights::for_profile(profile);
    let weighted_sum = signals.latency * w.latency
        + signals.cost * w.cost
        + signals.risk * w.risk
        + signals.energy * w.energy
        + signals.human_attention * w.human_attention
        + signals.hardware_pressure * w.hardware_pressure;
    let w_sum = w.sum();
    // Guard against zero-sum (would happen if EVERY weight is 0.0;
    // can't happen with the per-profile tables but is defensive).
    let compound = if w_sum > 0.0 {
        (weighted_sum / w_sum).clamp(0.0, 1.0)
    } else {
        0.0
    };
    AxisScores {
        latency: signals.latency,
        cost: signals.cost,
        risk: signals.risk,
        energy: signals.energy,
        human_attention: signals.human_attention,
        hardware_pressure: signals.hardware_pressure,
        compound,
    }
}

// ============================================================================
// Backpressure surfaces + thresholds + hysteresis (R11333-R11362)
// ============================================================================

/// Threshold table per R11333-R11349. Operator-tunable via
/// `/etc/selfdef/scheduler.toml`; values change requires MS003 multi-sig
/// (R11353).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct BackpressureThresholds {
    /// Blackwell VRAM high (R11333). Fraction in [0.0, 1.0].
    pub blackwell_vram_high: f32,
    /// 3090 GPU busy (R11337). Fraction in [0.0, 1.0].
    pub gpu3090_busy: f32,
    /// CPU PSI some/avg10 percent (R11340). Fraction in [0.0, 1.0].
    pub cpu_pressure: f32,
    /// Memory PSI some/avg10 percent (R11343).
    pub ram_pressure: f32,
    /// IO PSI some/avg10 percent (R11346).
    pub io_pressure: f32,
    /// Human gate queue depth (R11349).
    pub human_gate_queue_high: u32,
}

impl BackpressureThresholds {
    /// Default thresholds per R11333-R11349 (the operator-deployable baseline).
    #[must_use]
    pub const fn default_for_sain01() -> Self {
        Self {
            blackwell_vram_high: 0.90,
            gpu3090_busy: 0.80,
            cpu_pressure: 0.50,
            ram_pressure: 0.30,
            io_pressure: 0.40,
            human_gate_queue_high: 5,
        }
    }

    /// Hysteresis margin per R11357 — surface exits pressure when value
    /// drops below `threshold - hysteresis_margin` for 10s.
    pub const HYSTERESIS_MARGIN: f32 = 0.10;
}

/// Raw resource measurements (from PSI / DCGM / human-gate tracker).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct ResourceMeasurements {
    /// Blackwell VRAM utilization (0.0-1.0).
    pub blackwell_vram_util: f32,
    /// RTX 3090 GPU utilization (0.0-1.0).
    pub gpu3090_util: f32,
    /// CPU PSI some/avg10 (0.0-1.0).
    pub cpu_psi: f32,
    /// Memory PSI some/avg10 (0.0-1.0).
    pub mem_psi: f32,
    /// IO PSI some/avg10 (0.0-1.0).
    pub io_psi: f32,
    /// Human gate pending approval count.
    pub human_gate_queue_depth: u32,
}

impl ResourceMeasurements {
    /// Construct an all-clean measurement.
    #[must_use]
    pub const fn clean() -> Self {
        Self {
            blackwell_vram_util: 0.0,
            gpu3090_util: 0.0,
            cpu_psi: 0.0,
            mem_psi: 0.0,
            io_psi: 0.0,
            human_gate_queue_depth: 0,
        }
    }
}

/// Backpressure monitor — turns raw resource measurements into a
/// [`BackpressureState`] honoring thresholds + hysteresis per R11357.
#[derive(Debug, Clone)]
pub struct BackpressureMonitor {
    thresholds: BackpressureThresholds,
    last_state: BackpressureState,
}

impl BackpressureMonitor {
    /// Construct with default sain-01 thresholds + clean state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            thresholds: BackpressureThresholds::default_for_sain01(),
            last_state: BackpressureState::clean(),
        }
    }

    /// Construct with operator-tuned thresholds.
    #[must_use]
    pub fn with_thresholds(thresholds: BackpressureThresholds) -> Self {
        Self {
            thresholds,
            last_state: BackpressureState::clean(),
        }
    }

    /// Update state from a fresh measurement. Returns the new state.
    /// Honors hysteresis: a surface that was under pressure stays under
    /// pressure until its measurement drops below
    /// (threshold - HYSTERESIS_MARGIN). A surface that was clean enters
    /// pressure when its measurement crosses the threshold upward.
    pub fn update(&mut self, m: ResourceMeasurements) -> BackpressureState {
        let t = self.thresholds;
        let h = BackpressureThresholds::HYSTERESIS_MARGIN;
        let next = BackpressureState {
            blackwell_vram_high: enter_or_stay(
                self.last_state.blackwell_vram_high,
                m.blackwell_vram_util,
                t.blackwell_vram_high,
                h,
            ),
            gpu3090_busy: enter_or_stay(
                self.last_state.gpu3090_busy,
                m.gpu3090_util,
                t.gpu3090_busy,
                h,
            ),
            cpu_pressure: enter_or_stay(self.last_state.cpu_pressure, m.cpu_psi, t.cpu_pressure, h),
            ram_pressure: enter_or_stay(self.last_state.ram_pressure, m.mem_psi, t.ram_pressure, h),
            io_pressure: enter_or_stay(self.last_state.io_pressure, m.io_psi, t.io_pressure, h),
            human_gate_queue_high: m.human_gate_queue_depth > t.human_gate_queue_high,
        };
        self.last_state = next;
        next
    }

    /// Read the last-known state.
    #[must_use]
    pub const fn state(&self) -> BackpressureState {
        self.last_state
    }

    /// Read the threshold table.
    #[must_use]
    pub const fn thresholds(&self) -> BackpressureThresholds {
        self.thresholds
    }
}

impl Default for BackpressureMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Hysteresis rule per R11357.
fn enter_or_stay(was: bool, value: f32, threshold: f32, hysteresis: f32) -> bool {
    if was {
        // Already under pressure — exit only when value drops below threshold - hysteresis.
        value >= threshold - hysteresis
    } else {
        // Clean — enter pressure when value crosses threshold.
        value >= threshold
    }
}

// ============================================================================
// Decision audit log (R11366-R11392)
// ============================================================================

/// Errors produced by the runtime crate.
#[derive(Debug, Error)]
pub enum SchedulerError {
    /// Schema-version drift.
    #[error("schema version mismatch: expected {SCHEMA_VERSION}, got {0}")]
    SchemaMismatch(String),
    /// I/O error.
    #[error("io: {0}")]
    Io(String),
    /// JSON parse / serialize error.
    #[error("serde_json: {0}")]
    Serde(String),
    /// Audit chain integrity broken.
    #[error("audit chain break at line {line}: {detail}")]
    AuditChainBreak {
        /// Line number in the audit jsonl file.
        line: usize,
        /// What was wrong.
        detail: String,
    },
    /// Decision validation failed.
    #[error("decision invalid: {0}")]
    InvalidDecision(String),
}

/// Append a Decision to the audit log with SHA-256 chained
/// `prev_event_sha256` field per R11366-R11367.
///
/// Atomic O_APPEND + fsync. Creates parent dirs if missing.
///
/// # Errors
/// Returns `SchedulerError::Io` on file I/O failure, `SchedulerError::Serde`
/// on serialization failure.
pub fn emit_audit_entry(audit_log: &Path, decision: &Decision) -> Result<(), SchedulerError> {
    if let Some(parent) = audit_log.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| SchedulerError::Io(e.to_string()))?;
        }
    }
    let prev_sha = last_line_sha256(audit_log)?;
    let entry = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "ts_ms": decision.ts_ms,
        "hostname": decision.hostname,
        "request_id": decision.request_id,
        "profile": decision.profile,
        "route": decision.route,
        "axis_scores": decision.axis_scores,
        "backpressure": decision.backpressure,
        "signer_kid_policy": decision.signer_kid_policy,
        "override_signer_kid": decision.override_signer_kid,
        "rationale": decision.rationale,
        "prev_event_sha256": prev_sha,
    });
    let line = serde_json::to_string(&entry).map_err(|e| SchedulerError::Serde(e.to_string()))?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit_log)
        .map_err(|e| SchedulerError::Io(e.to_string()))?;
    writeln!(f, "{line}").map_err(|e| SchedulerError::Io(e.to_string()))?;
    f.sync_all()
        .map_err(|e| SchedulerError::Io(e.to_string()))?;
    Ok(())
}

fn last_line_sha256(path: &Path) -> Result<Option<String>, SchedulerError> {
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(path).map_err(|e| SchedulerError::Io(e.to_string()))?;
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

/// Verify the audit chain integrity per R11367.
///
/// # Errors
/// Returns `SchedulerError::AuditChainBreak` on chain break, malformed
/// JSON, or missing prev_event_sha256 on non-first event.
pub fn audit_chain_check(audit_log: &Path) -> Result<usize, SchedulerError> {
    if !audit_log.exists() {
        return Ok(0);
    }
    let text = fs::read_to_string(audit_log).map_err(|e| SchedulerError::Io(e.to_string()))?;
    let mut last_sha: Option<String> = None;
    let mut events = 0usize;
    for (idx, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let parsed: serde_json::Value =
            serde_json::from_str(line).map_err(|e| SchedulerError::AuditChainBreak {
                line: idx + 1,
                detail: format!("malformed JSON: {e}"),
            })?;
        let claimed_prev = parsed
            .get("prev_event_sha256")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        match (&last_sha, claimed_prev.as_deref()) {
            (Some(want), Some(got)) if got != want => {
                return Err(SchedulerError::AuditChainBreak {
                    line: idx + 1,
                    detail: format!("prev_event_sha256={got}, expected {want}"),
                });
            }
            (Some(_), None) => {
                return Err(SchedulerError::AuditChainBreak {
                    line: idx + 1,
                    detail: "prev_event_sha256 missing from non-first event".into(),
                });
            }
            _ => {}
        }
        let mut h = Sha256::new();
        h.update(line.as_bytes());
        last_sha = Some(format!("{:x}", h.finalize()));
        events += 1;
    }
    Ok(events)
}

// ============================================================================
// Replay engine (R11393-R11398)
// ============================================================================

/// Result of a counterfactual replay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReplayResult {
    /// The original decision (read from audit log).
    pub original: Decision,
    /// The decision that would have been made under the requested
    /// `replay_profile` (if `replay_profile` differs from the original).
    pub counterfactual: Decision,
    /// Whether the route differs between original and counterfactual.
    pub route_differs: bool,
    /// Whether the compound score differs (within ε=0.001).
    pub compound_differs: bool,
}

/// Replay an original decision against a (possibly different) profile.
/// NEVER re-executes the request — read-only per R11394.
///
/// The signals from the original decision are reused; only the profile-
/// dependent weights change. The result lets the operator inspect "what
/// would have happened under `replay_profile`".
#[must_use]
pub fn replay(original: &Decision, replay_profile: Profile) -> ReplayResult {
    // Reconstruct signals from the original axis_scores. Since signals
    // are the unweighted axis values, they equal the latency/cost/risk/
    // energy/human_attention/hardware_pressure fields of axis_scores.
    let signals = AxisSignals {
        latency: original.axis_scores.latency,
        cost: original.axis_scores.cost,
        risk: original.axis_scores.risk,
        energy: original.axis_scores.energy,
        human_attention: original.axis_scores.human_attention,
        hardware_pressure: original.axis_scores.hardware_pressure,
    };
    let new_scores = evaluate_objective(signals, replay_profile);
    let counterfactual = Decision {
        schema_version: original.schema_version.clone(),
        request_id: original.request_id.clone(),
        profile: replay_profile,
        // Route may or may not change — without re-running the request
        // we can't know for sure; but we can compute an inferred route
        // by picking the highest-scoring tier. For Stage-1 we keep the
        // original route and surface compound_differs so the operator
        // can investigate. Full route inference lands in a later round.
        route: original.route,
        axis_scores: new_scores,
        backpressure: original.backpressure,
        ts_ms: original.ts_ms,
        hostname: original.hostname.clone(),
        signer_kid_policy: original.signer_kid_policy.clone(),
        override_signer_kid: original.override_signer_kid.clone(),
        rationale: format!(
            "REPLAY against {:?}: {}",
            replay_profile, original.rationale
        ),
    };
    let route_differs = counterfactual.route != original.route;
    let compound_differs =
        (counterfactual.axis_scores.compound - original.axis_scores.compound).abs() > 0.001;
    ReplayResult {
        original: original.clone(),
        counterfactual,
        route_differs,
        compound_differs,
    }
}

// ============================================================================
// Scheduler orchestrator + ring-buffer reader
// ============================================================================

/// Current wall-clock as epoch ms.
#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Read the scheduler ring buffer directory into Decisions (newest-first).
/// Returns empty vec on missing dir.
///
/// # Errors
/// Returns `SchedulerError::Io` on read failure of an existing dir.
pub fn read_ring_buffer(ring: &Path) -> Result<Vec<Decision>, SchedulerError> {
    if !ring.exists() {
        return Ok(Vec::new());
    }
    let mut out: Vec<Decision> = Vec::new();
    for dirent in fs::read_dir(ring).map_err(|e| SchedulerError::Io(e.to_string()))? {
        let dirent = dirent.map_err(|e| SchedulerError::Io(e.to_string()))?;
        let path = dirent.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if let Ok(d) = serde_json::from_slice::<Decision>(&bytes) {
            if d.validate().is_ok() {
                out.push(d);
            }
        }
    }
    out.sort_by_key(|d| std::cmp::Reverse(d.ts_ms));
    Ok(out)
}

/// Default bounded retention for the decision ring buffer — the newest
/// `DEFAULT_RING_MAX_ENTRIES` decisions are kept; older files are evicted
/// FIFO. Matches the `/v1/scheduler/history` `limit` ceiling (256) so the
/// HTTP surface can always serve the full retained window.
pub const DEFAULT_RING_MAX_ENTRIES: usize = 256;

/// Sanitize a request id into a filename-safe token (keep `[A-Za-z0-9._-]`,
/// replace anything else with `_`). UUIDv7 request ids are already safe;
/// this defends against an operator-forced id with odd characters.
fn sanitize_for_filename(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Append a [`Decision`] to the ring-buffer directory that
/// [`read_ring_buffer`] consumes, then evict oldest entries beyond
/// `max_entries` (FIFO by `ts_ms`-prefixed filename).
///
/// Each decision is written as one `<ts_ms:020>-<request_id>.json` file
/// containing exactly the serialized [`Decision`] (the shape
/// `read_ring_buffer` deserializes). Write is atomic — a temp file in the
/// same directory is `rename(2)`-d into place — so a concurrent reader never
/// sees a half-written file. `max_entries == 0` disables retention (keep
/// all).
///
/// This is the writer half of the scheduler observability surface: the
/// orchestrator persists each decision here so `GET /v1/scheduler`,
/// `/history`, and `/explain` (which all read the ring) actually surface the
/// decisions it makes.
///
/// # Errors
/// Returns [`SchedulerError::Io`] on directory create / write / rename
/// failure, or [`SchedulerError::Serde`] on serialization failure.
pub fn write_ring_buffer(
    ring: &Path,
    decision: &Decision,
    max_entries: usize,
) -> Result<(), SchedulerError> {
    fs::create_dir_all(ring).map_err(|e| SchedulerError::Io(e.to_string()))?;

    let json = serde_json::to_string(decision).map_err(|e| SchedulerError::Serde(e.to_string()))?;
    let stem = format!(
        "{:020}-{}",
        decision.ts_ms,
        sanitize_for_filename(&decision.request_id)
    );
    let final_path = ring.join(format!("{stem}.json"));
    let tmp_path = ring.join(format!(
        ".{stem}.tmp.{}.{}",
        std::process::id(),
        now_ms()
    ));

    {
        let mut f = fs::File::create(&tmp_path).map_err(|e| SchedulerError::Io(e.to_string()))?;
        f.write_all(json.as_bytes())
            .map_err(|e| SchedulerError::Io(e.to_string()))?;
        f.sync_all().map_err(|e| SchedulerError::Io(e.to_string()))?;
    }
    fs::rename(&tmp_path, &final_path).map_err(|e| {
        // best-effort cleanup of the temp file on rename failure
        let _ = fs::remove_file(&tmp_path);
        SchedulerError::Io(e.to_string())
    })?;

    if max_entries > 0 {
        evict_ring_overflow(ring, max_entries)?;
    }
    Ok(())
}

/// Keep only the newest `max_entries` `*.json` files in `ring` (oldest-first
/// eviction by the `ts_ms`-prefixed filename, which sorts chronologically).
fn evict_ring_overflow(ring: &Path, max_entries: usize) -> Result<(), SchedulerError> {
    let mut files: Vec<PathBuf> = fs::read_dir(ring)
        .map_err(|e| SchedulerError::Io(e.to_string()))?
        .filter_map(Result::ok)
        .map(|d| d.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    if files.len() <= max_entries {
        return Ok(());
    }
    files.sort(); // ts_ms-zero-padded prefix ⇒ lexicographic == chronological
    let remove_count = files.len() - max_entries;
    for p in files.into_iter().take(remove_count) {
        let _ = fs::remove_file(p); // best-effort; a racing reader skips it
    }
    Ok(())
}

/// Default config: the audit log and ring paths.
#[must_use]
pub fn default_audit_log() -> PathBuf {
    PathBuf::from(DEFAULT_AUDIT_LOG_PATH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ------------------------- per-profile rule tests -----------------------

    #[test]
    fn fast_profile_rules_dump_18011_18014_verbatim() {
        let r = ProfileRules::for_profile(Profile::Fast);
        assert!(r.favor_latency);
        assert!(r.scout_first);
        assert!(!r.oracle_verification_required);
        assert!(!r.tests_required);
    }

    #[test]
    fn careful_profile_rules_dump_18016_18019_verbatim() {
        let r = ProfileRules::for_profile(Profile::Careful);
        assert!(!r.favor_latency);
        assert!(r.oracle_verification_required);
        assert!(r.tests_required);
    }

    #[test]
    fn private_profile_rules_dump_18021_18024_verbatim() {
        let r = ProfileRules::for_profile(Profile::Private);
        assert!(r.cloud_disabled);
        assert!(r.strict_memory_exposure);
    }

    #[test]
    fn autonomous_profile_rules_dump_18026_18030_verbatim() {
        let r = ProfileRules::for_profile(Profile::Autonomous);
        assert!(r.sandbox_first);
        assert!(r.checkpoint_often);
        assert!(r.batch_approvals);
    }

    #[test]
    fn experimental_profile_rules_dump_18032_18035_verbatim() {
        let r = ProfileRules::for_profile(Profile::Experimental);
        assert!(r.wide_branch_search);
        assert!(r.sandbox_first);
        assert!(r.no_host_commit);
    }

    #[test]
    fn production_profile_rules_dump_18037_18040_verbatim() {
        let r = ProfileRules::for_profile(Profile::Production);
        assert!(r.strict_commit_gates);
        assert!(r.low_variance);
        assert!(r.strong_observability);
    }

    // ------------------------- per-profile weight tests ---------------------

    #[test]
    fn fast_weights_r11291_r11296() {
        let w = AxisWeights::for_profile(Profile::Fast);
        assert_eq!(w.latency, 1.0);
        assert_eq!(w.cost, 0.3);
        assert_eq!(w.risk, 0.3);
    }

    #[test]
    fn careful_weights_r11297_r11302() {
        let w = AxisWeights::for_profile(Profile::Careful);
        assert_eq!(w.risk, 1.0);
        assert_eq!(w.human_attention, 0.9);
        assert_eq!(w.hardware_pressure, 0.9);
    }

    #[test]
    fn private_cost_weight_is_zero_per_r11304() {
        let w = AxisWeights::for_profile(Profile::Private);
        assert_eq!(w.cost, 0.0);
    }

    #[test]
    fn production_weights_r11321_r11326() {
        let w = AxisWeights::for_profile(Profile::Production);
        assert_eq!(w.latency, 0.9);
        assert_eq!(w.risk, 1.0);
    }

    #[test]
    fn weights_sum_positive_for_all_profiles() {
        for p in Profile::all() {
            let w = AxisWeights::for_profile(*p);
            assert!(w.sum() > 0.0, "{p:?} sum was zero");
        }
    }

    // ------------------------- objective evaluator -------------------------

    fn all_one_signals() -> AxisSignals {
        AxisSignals {
            latency: 1.0,
            cost: 1.0,
            risk: 1.0,
            energy: 1.0,
            human_attention: 1.0,
            hardware_pressure: 1.0,
        }
    }

    #[test]
    fn all_one_signals_compound_to_1() {
        for p in Profile::all() {
            let scores = evaluate_objective(all_one_signals(), *p);
            assert!(
                (scores.compound - 1.0).abs() < 0.001,
                "{:?} compound was {}",
                p,
                scores.compound
            );
        }
    }

    #[test]
    fn all_zero_signals_compound_to_0() {
        let signals = AxisSignals {
            latency: 0.0,
            cost: 0.0,
            risk: 0.0,
            energy: 0.0,
            human_attention: 0.0,
            hardware_pressure: 0.0,
        };
        for p in Profile::all() {
            let scores = evaluate_objective(signals, *p);
            assert!(
                scores.compound.abs() < 0.001,
                "{:?} compound was {}",
                p,
                scores.compound
            );
        }
    }

    #[test]
    fn fast_profile_weights_latency_heavily() {
        // Fast: latency=1.0, others < 0.5
        // Signal: latency=0 (bad), others=1.0. Fast should penalize this MORE than careful.
        let bad_latency = AxisSignals {
            latency: 0.0,
            cost: 1.0,
            risk: 1.0,
            energy: 1.0,
            human_attention: 1.0,
            hardware_pressure: 1.0,
        };
        let fast_score = evaluate_objective(bad_latency, Profile::Fast).compound;
        let careful_score = evaluate_objective(bad_latency, Profile::Careful).compound;
        assert!(
            fast_score < careful_score,
            "fast={fast_score} careful={careful_score}"
        );
    }

    #[test]
    fn careful_profile_weights_risk_heavily() {
        // Careful: risk=1.0, others ≤ 0.9
        let bad_risk = AxisSignals {
            latency: 1.0,
            cost: 1.0,
            risk: 0.0,
            energy: 1.0,
            human_attention: 1.0,
            hardware_pressure: 1.0,
        };
        let careful_score = evaluate_objective(bad_risk, Profile::Careful).compound;
        let fast_score = evaluate_objective(bad_risk, Profile::Fast).compound;
        assert!(
            careful_score < fast_score,
            "careful={careful_score} fast={fast_score}"
        );
    }

    #[test]
    fn private_profile_cost_irrelevant() {
        // Private has cost weight 0.0 — changing cost signal should not affect compound.
        let signals_a = all_one_signals();
        let mut signals_b = signals_a;
        signals_b.cost = 0.0;
        let a = evaluate_objective(signals_a, Profile::Private).compound;
        let b = evaluate_objective(signals_b, Profile::Private).compound;
        assert!((a - b).abs() < 0.001);
    }

    // ------------------------- backpressure ----------------------------------

    #[test]
    fn backpressure_clean_under_threshold() {
        let mut mon = BackpressureMonitor::new();
        let state = mon.update(ResourceMeasurements::clean());
        assert!(!state.any_pressure());
    }

    #[test]
    fn backpressure_blackwell_vram_enter_pressure_at_threshold() {
        let mut mon = BackpressureMonitor::new();
        let mut m = ResourceMeasurements::clean();
        m.blackwell_vram_util = 0.95;
        let s = mon.update(m);
        assert!(s.blackwell_vram_high);
    }

    #[test]
    fn backpressure_hysteresis_stays_under_pressure_within_margin() {
        let mut mon = BackpressureMonitor::new();
        let mut m = ResourceMeasurements::clean();
        m.blackwell_vram_util = 0.95;
        mon.update(m);
        // Drop to 0.85 — above threshold(0.90) - hysteresis(0.10) = 0.80, so STAYS under pressure.
        m.blackwell_vram_util = 0.85;
        let s = mon.update(m);
        assert!(s.blackwell_vram_high);
    }

    #[test]
    fn backpressure_hysteresis_exits_below_margin() {
        let mut mon = BackpressureMonitor::new();
        let mut m = ResourceMeasurements::clean();
        m.blackwell_vram_util = 0.95;
        mon.update(m);
        // Drop to 0.79 — below threshold(0.90) - hysteresis(0.10) = 0.80, so EXITS pressure.
        m.blackwell_vram_util = 0.79;
        let s = mon.update(m);
        assert!(!s.blackwell_vram_high);
    }

    #[test]
    fn backpressure_human_gate_above_threshold() {
        let mut mon = BackpressureMonitor::new();
        let mut m = ResourceMeasurements::clean();
        m.human_gate_queue_depth = 10; // threshold is 5
        let s = mon.update(m);
        assert!(s.human_gate_queue_high);
    }

    // ------------------------- audit chain -----------------------------------

    fn sample_decision(ts_ms: u64) -> Decision {
        Decision::new(
            format!("req-{ts_ms}"),
            Profile::Careful,
            Route::Blackwell,
            evaluate_objective(all_one_signals(), Profile::Careful),
            BackpressureState::clean(),
            ts_ms,
            "host-A",
            "kid-policy-1",
            "test decision",
        )
    }

    #[test]
    fn emit_audit_entry_writes_one_jsonl_line() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("audit.log");
        emit_audit_entry(&log, &sample_decision(1_700_000_000_000)).unwrap();
        let text = fs::read_to_string(&log).unwrap();
        assert_eq!(text.lines().count(), 1);
    }

    #[test]
    fn emit_audit_chains_prev_sha256() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("audit.log");
        emit_audit_entry(&log, &sample_decision(1_000_000_000_000)).unwrap();
        emit_audit_entry(&log, &sample_decision(1_000_000_000_001)).unwrap();
        let text = fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let l2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        let prev = l2["prev_event_sha256"].as_str().expect("chained");
        let mut h = Sha256::new();
        h.update(lines[0].as_bytes());
        assert_eq!(prev, format!("{:x}", h.finalize()));
    }

    #[test]
    fn audit_chain_check_clean_pass() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("audit.log");
        for i in 0..3u64 {
            emit_audit_entry(&log, &sample_decision(1_000_000_000_000 + i)).unwrap();
        }
        let n = audit_chain_check(&log).unwrap();
        assert_eq!(n, 3);
    }

    #[test]
    fn audit_chain_check_detects_break() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("audit.log");
        let l1 = r#"{"schema_version":"1.0.0"}"#;
        let l2 = r#"{"schema_version":"1.0.0","prev_event_sha256":"bogus"}"#;
        fs::write(&log, format!("{l1}\n{l2}\n")).unwrap();
        let err = audit_chain_check(&log).unwrap_err();
        assert!(matches!(
            err,
            SchedulerError::AuditChainBreak { line: 2, .. }
        ));
    }

    #[test]
    fn audit_chain_check_missing_returns_zero() {
        let dir = TempDir::new().unwrap();
        let n = audit_chain_check(&dir.path().join("nope")).unwrap();
        assert_eq!(n, 0);
    }

    // ------------------------- replay ---------------------------------------

    #[test]
    fn replay_against_same_profile_keeps_compound() {
        let d = sample_decision(1);
        let r = replay(&d, Profile::Careful);
        assert!(!r.compound_differs);
    }

    #[test]
    fn replay_against_different_profile_changes_compound() {
        let d = sample_decision(1);
        let _r = replay(&d, Profile::Fast);
        // Careful→Fast has different weights; compound should differ for non-uniform signals.
        // sample_decision uses all_one_signals which gives compound=1.0 under any profile,
        // so we need different signals to see a change. Construct a decision with skew.
        let signals_skew = AxisSignals {
            latency: 0.2,
            cost: 1.0,
            risk: 1.0,
            energy: 1.0,
            human_attention: 1.0,
            hardware_pressure: 1.0,
        };
        let scores = evaluate_objective(signals_skew, Profile::Careful);
        let d2 = Decision::new(
            "req-skew",
            Profile::Careful,
            Route::Blackwell,
            scores,
            BackpressureState::clean(),
            1,
            "h",
            "k",
            "r",
        );
        let r2 = replay(&d2, Profile::Fast);
        // Fast cares much more about latency → compound should drop.
        assert!(r2.compound_differs);
        assert!(r2.counterfactual.axis_scores.compound < d2.axis_scores.compound);
        // (Stage-1 keeps route unchanged on replay)
        assert!(!r2.route_differs);
    }

    // ------------------------- ring buffer ----------------------------------

    #[test]
    fn ring_buffer_missing_returns_empty() {
        let dir = TempDir::new().unwrap();
        let v = read_ring_buffer(&dir.path().join("nope")).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn ring_buffer_newest_first() {
        let dir = TempDir::new().unwrap();
        let ring = dir.path().join("ring");
        fs::create_dir_all(&ring).unwrap();
        for (name, ts) in [("a", 100_u64), ("b", 300), ("c", 200)] {
            fs::write(
                ring.join(format!("{name}.json")),
                serde_json::to_vec(&sample_decision(ts)).unwrap(),
            )
            .unwrap();
        }
        let out = read_ring_buffer(&ring).unwrap();
        let ts: Vec<u64> = out.iter().map(|d| d.ts_ms).collect();
        assert_eq!(ts, vec![300, 200, 100]);
    }

    #[test]
    fn ring_buffer_skips_malformed() {
        let dir = TempDir::new().unwrap();
        let ring = dir.path().join("ring");
        fs::create_dir_all(&ring).unwrap();
        fs::write(ring.join("bad.json"), b"{not json").unwrap();
        fs::write(
            ring.join("good.json"),
            serde_json::to_vec(&sample_decision(1)).unwrap(),
        )
        .unwrap();
        let out = read_ring_buffer(&ring).unwrap();
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn write_ring_buffer_roundtrips_through_reader() {
        let dir = TempDir::new().unwrap();
        let ring = dir.path().join("ring");
        write_ring_buffer(&ring, &sample_decision(500), DEFAULT_RING_MAX_ENTRIES).unwrap();
        write_ring_buffer(&ring, &sample_decision(700), DEFAULT_RING_MAX_ENTRIES).unwrap();
        write_ring_buffer(&ring, &sample_decision(600), DEFAULT_RING_MAX_ENTRIES).unwrap();
        let out = read_ring_buffer(&ring).unwrap();
        let ts: Vec<u64> = out.iter().map(|d| d.ts_ms).collect();
        // reader sorts newest-first
        assert_eq!(ts, vec![700, 600, 500]);
    }

    #[test]
    fn write_ring_buffer_creates_dir_if_missing() {
        let dir = TempDir::new().unwrap();
        let ring = dir.path().join("nested").join("ring");
        assert!(!ring.exists());
        write_ring_buffer(&ring, &sample_decision(1), DEFAULT_RING_MAX_ENTRIES).unwrap();
        assert_eq!(read_ring_buffer(&ring).unwrap().len(), 1);
    }

    #[test]
    fn write_ring_buffer_evicts_oldest_beyond_max() {
        let dir = TempDir::new().unwrap();
        let ring = dir.path().join("ring");
        // write 5 decisions with ascending ts, retain only 3
        for ts in [10_u64, 20, 30, 40, 50] {
            write_ring_buffer(&ring, &sample_decision(ts), 3).unwrap();
        }
        let out = read_ring_buffer(&ring).unwrap();
        let ts: Vec<u64> = out.iter().map(|d| d.ts_ms).collect();
        // newest 3 kept, oldest (10, 20) evicted
        assert_eq!(ts, vec![50, 40, 30]);
    }

    #[test]
    fn write_ring_buffer_zero_max_keeps_all() {
        let dir = TempDir::new().unwrap();
        let ring = dir.path().join("ring");
        for ts in [1_u64, 2, 3, 4] {
            write_ring_buffer(&ring, &sample_decision(ts), 0).unwrap();
        }
        assert_eq!(read_ring_buffer(&ring).unwrap().len(), 4);
    }

    #[test]
    fn sanitize_for_filename_replaces_unsafe_chars() {
        assert_eq!(sanitize_for_filename("req-0190abcd_7e11.7"), "req-0190abcd_7e11.7");
        assert_eq!(sanitize_for_filename("a/b c:d"), "a_b_c_d");
    }
}
