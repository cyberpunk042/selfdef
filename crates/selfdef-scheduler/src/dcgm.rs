//! `selfdef-scheduler::dcgm` — M01157: NVIDIA GPU pressure source
//! (Data Center GPU Manager bridge) for the Goldilocks Scheduler
//! backpressure surface.
//!
//! Dump grounding (avx-plus-plus 2026-05-18 line 18197):
//! > *"Linux PSI + DCGM + trace metrics feed the scheduler"*
//!
//! Per-GPU dump grounding (lines 18281-18287):
//! ```text
//! RTX PRO 6000 Blackwell:  oracle  (large resident models, long context, final reasoning, verification)
//! RTX 3090:                scout   (SLMs, drafts, embeddings, perception, sandboxed exploration)
//! ```
//!
//! Catalog grounding: MS048 module `M01157 selfdef-scheduler-dcgm-source
//! (NVIDIA DCGM)` per `~/selfdef/backlog/milestones/
//! MS048-goldilocks-scheduler-hardware-aware-resource-routing.md`.
//!
//! Doctrinal anchor: [Peace Machine + Core Law](https://github.com/
//! cyberpunk042/devops-solutions-information-hub/blob/main/wiki/spine/
//! doctrine/peace-machine-and-core-law.md) — Core Law clause
//! "Runtime routes" (MS048's owned clause) + peace-machine clause
//! "disciplined enough to explain itself" (every GPU reading is
//! timestamped + auditable).
//!
//! ## What this module provides
//!
//! 1. `DcgmReading` — a single timestamped snapshot of all
//!    configured GPUs (Blackwell oracle + 3090 scout in the sain-01
//!    baseline; extensible to additional GPUs via
//!    `DcgmGpuIndices`).
//! 2. `GpuReading` — per-GPU measurement quintuple
//!    (utilization / vram_used / vram_total / temperature_c /
//!    power_w) with convenience accessors `vram_util_fraction()`
//!    and `gpu_util_fraction()` matching the
//!    `BackpressureThresholds.blackwell_vram_high` and
//!    `gpu3090_busy` semantics (R11333-R11337).
//! 3. `DcgmSource` trait — Effector-style stubbable boundary the
//!    scheduler's `BackpressureMonitor` calls into. Trait shape
//!    per the existing `selfdef_scheduler` crate doc comment.
//! 4. `parse_nvidia_smi_csv` — parser for the CSV-output form of
//!    `nvidia-smi --query-gpu=index,utilization.gpu,memory.used,
//!    memory.total,temperature.gpu,power.draw --format=csv,noheader,
//!    nounits` — the canonical user-space tool's machine-readable
//!    surface (same format both DCGM and the operator's existing
//!    dashboards consume).
//! 5. `NvidiaSmiDcgmSource` — real-substrate impl invoking
//!    `nvidia-smi` as a subprocess. Honest-offline: if `nvidia-smi`
//!    is not on PATH, exits non-zero, or no GPUs are visible,
//!    `read()` returns `DcgmError::Unavailable` (no fabricated
//!    zeros).
//! 6. `MockDcgmSource` — test injector with `with_blackwell_*` /
//!    `with_gpu3090_*` builder chain.
//! 7. `DcgmError` — typed errors (`CommandIo` / `CommandExit` /
//!    `Parse` / `Unavailable` / `GpuMissing`) so callers
//!    distinguish substrate-absent from substrate-broken from
//!    misconfigured-GPU-index.
//!
//! ## Why nvidia-smi (not libdcgm directly)
//!
//! DCGM is delivered as a heavyweight C library (`libdcgm`) with
//! shared-state + daemonized exporter. `nvidia-smi` is the same
//! NVML-backed user-space tool both DCGM CLIs and operators use,
//! and its CSV output is stable, sub-50ms, and zero-dep at the
//! Rust side. The trait abstraction means a future `libdcgm`
//! native impl can drop in without callers changing — `DcgmSource`
//! is the contract; `NvidiaSmiDcgmSource` is one implementation
//! among many (cf. M01151 selfdef-scheduler-blackwell-gpu for
//! a future native-NVML impl).
//!
//! ## Non-goals
//!
//! - Not a Prometheus exporter. Per-GPU metric emission for
//!   Grafana + sovereign-os cockpit lives in M01168 prometheus-
//!   exporter — separate slot.
//! - Not a process-attribution layer. Per-pid VRAM usage requires
//!   `nvidia-smi pmon` or libdcgm's per-process queries; this
//!   module surfaces aggregate per-GPU state only.
//! - Not a multi-host fleet collector. `NvidiaSmiDcgmSource` reads
//!   only the local host's GPUs. Fleet-wide aggregation lives in
//!   sovereign-os's observability layer.
//!
//! Standing rule: We do not minimize anything.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default `nvidia-smi` binary path used by `NvidiaSmiDcgmSource::new`.
/// Production hosts have `nvidia-smi` on PATH; the test suite passes
/// a fixture binary path via `with_command_path`.
pub const DEFAULT_NVIDIA_SMI_BIN: &str = "nvidia-smi";

/// The CSV query string the source asks `nvidia-smi` to emit.
/// Fields are stable across NVIDIA driver releases and are the same
/// six columns the operator's existing Grafana dashboards consume.
pub const NVIDIA_SMI_QUERY: &str =
    "index,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw";

/// CSV format flags. `noheader` suppresses the human row; `nounits`
/// strips ` MiB` / ` W` / ` %` suffixes so each field parses as a
/// plain f32/u64.
pub const NVIDIA_SMI_FORMAT: &str = "csv,noheader,nounits";

// ============================================================================
// DcgmGpuIndices
// ============================================================================

/// Which `nvidia-smi`-reported `index` corresponds to which logical
/// role (oracle / scout). Per the sain-01 dump architecture
/// (lines 18281-18287), the baseline mapping is `blackwell=0` /
/// `gpu3090=1`. Operators with a different bus topology can
/// override via `selfdef-scheduler.toml` or the
/// `DcgmGpuIndices::custom` constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DcgmGpuIndices {
    /// `nvidia-smi index` of the RTX PRO 6000 Blackwell oracle.
    pub blackwell: u32,
    /// `nvidia-smi index` of the RTX 3090 scout.
    pub gpu3090: u32,
}

impl DcgmGpuIndices {
    /// sain-01 baseline (Blackwell index 0, 3090 index 1).
    #[must_use]
    pub const fn sain01_baseline() -> Self {
        Self {
            blackwell: 0,
            gpu3090: 1,
        }
    }

    /// Custom mapping for hosts where the topology differs.
    #[must_use]
    pub const fn custom(blackwell: u32, gpu3090: u32) -> Self {
        Self { blackwell, gpu3090 }
    }
}

impl Default for DcgmGpuIndices {
    fn default() -> Self {
        Self::sain01_baseline()
    }
}

// ============================================================================
// GpuReading + DcgmReading
// ============================================================================

/// One per-GPU measurement row.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GpuReading {
    /// `nvidia-smi` reported index.
    pub index: u32,
    /// Compute utilization (0.0–1.0). The R11337 `gpu3090_busy`
    /// threshold matches against this field for the 3090.
    pub utilization: f32,
    /// VRAM currently in use, in mebibytes (MiB).
    pub vram_used_mib: u64,
    /// Total VRAM, in mebibytes. Divide `vram_used_mib` by this to
    /// get the fraction used (matches R11333 `blackwell_vram_high`).
    pub vram_total_mib: u64,
    /// GPU temperature in degrees Celsius. Surface for thermal
    /// backpressure; not yet in `BackpressureThresholds` (deferred
    /// to M01155 future expansion).
    pub temperature_c: f32,
    /// Instantaneous power draw in watts. Surface for energy axis
    /// of the 7-axis objective function (R11332 doctrinal anchor).
    pub power_w: f32,
}

impl GpuReading {
    /// VRAM utilization as fraction 0.0–1.0. If `vram_total_mib`
    /// is 0 (impossible on a real GPU; possible in a malformed
    /// mock), returns 0.0 rather than divide by zero.
    #[must_use]
    pub fn vram_util_fraction(&self) -> f32 {
        if self.vram_total_mib == 0 {
            return 0.0;
        }
        // Use f64 for the intermediate so a 24576 MiB Blackwell with
        // 22000 MiB used doesn't lose precision when cast back to f32.
        let used = self.vram_used_mib as f64;
        let total = self.vram_total_mib as f64;
        (used / total) as f32
    }

    /// Compute utilization as fraction (alias for `utilization`).
    /// Provided so callers parallel the `vram_util_fraction()` shape.
    #[must_use]
    pub fn gpu_util_fraction(&self) -> f32 {
        self.utilization
    }

    /// All-clean reading (test fixture).
    #[must_use]
    pub const fn clean(index: u32) -> Self {
        Self {
            index,
            utilization: 0.0,
            vram_used_mib: 0,
            vram_total_mib: 0,
            temperature_c: 0.0,
            power_w: 0.0,
        }
    }
}

/// Triple-ish (two named GPUs + any others observed but not assigned
/// a role) snapshot at one instant. The scheduler's
/// `BackpressureMonitor` consumes `blackwell.vram_util_fraction()`
/// for the R11333 `blackwell_vram_high` check and
/// `gpu3090.gpu_util_fraction()` for R11337 `gpu3090_busy`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DcgmReading {
    /// Wall-clock unix microseconds when the sample was taken.
    pub captured_at_unix_micros: u128,
    /// Index mapping in effect when the sample was taken (for
    /// audit + replay correctness).
    pub indices: DcgmGpuIndices,
    /// Blackwell oracle reading (looked up by `indices.blackwell`).
    pub blackwell: GpuReading,
    /// 3090 scout reading (looked up by `indices.gpu3090`).
    pub gpu3090: GpuReading,
    /// Any additional GPUs observed beyond the named two. Empty
    /// in the sain-01 baseline; populated on hosts with extra
    /// accelerators (future fleet members).
    pub others: Vec<GpuReading>,
}

impl DcgmReading {
    /// Convenience accessor: Blackwell VRAM fraction.
    #[must_use]
    pub fn blackwell_vram_util(&self) -> f32 {
        self.blackwell.vram_util_fraction()
    }

    /// Convenience accessor: 3090 compute utilization.
    #[must_use]
    pub fn gpu3090_util(&self) -> f32 {
        self.gpu3090.gpu_util_fraction()
    }
}

// ============================================================================
// DcgmError
// ============================================================================

/// Errors emitted by [`DcgmSource`] implementations.
#[derive(Debug, Error)]
pub enum DcgmError {
    /// `nvidia-smi` subprocess failed to spawn / read stdout.
    #[error("dcgm command IO: {0}")]
    CommandIo(#[from] std::io::Error),
    /// `nvidia-smi` exited non-zero. `stderr` is captured for audit.
    #[error("dcgm command exit code {code}; stderr: {stderr}")]
    CommandExit {
        /// Process exit code (or -1 if killed by signal).
        code: i32,
        /// Captured stderr (truncated to first 1KiB).
        stderr: String,
    },
    /// CSV parse failed. `line` is the offending row.
    #[error("dcgm parse: line {line:?}: {reason}")]
    Parse {
        /// Raw CSV line that failed.
        line: String,
        /// Human reason.
        reason: String,
    },
    /// `nvidia-smi` not found / no NVIDIA driver / no GPUs visible.
    /// Honest-offline marker: callers surface a
    /// `dcgm_available=0` gauge or equivalent.
    #[error("dcgm unavailable: {0}")]
    Unavailable(String),
    /// A configured GPU index (`blackwell` or `gpu3090`) was not
    /// present in the `nvidia-smi` output. Indicates topology
    /// drift — operator should update `DcgmGpuIndices`.
    #[error("dcgm gpu index {index} missing from output (observed indices: {observed:?})")]
    GpuMissing {
        /// The index that was configured but not found.
        index: u32,
        /// Indices that were observed.
        observed: Vec<u32>,
    },
}

// ============================================================================
// Parser
// ============================================================================

/// Parse one CSV row from `nvidia-smi --format=csv,noheader,nounits`
/// with the [`NVIDIA_SMI_QUERY`] columns.
///
/// Expected format:
///
/// ```text
/// 0, 35, 22000, 24576, 67, 220.5
/// ```
///
/// Tolerates trailing whitespace + empty trailing lines. Returns
/// `Ok(None)` on whitespace-only input so callers can iterate
/// stdout linewise.
///
/// # Errors
///
/// Returns `DcgmError::Parse` if any of the six fields are missing
/// or fail to parse as their expected type.
pub fn parse_nvidia_smi_line(line: &str) -> Result<Option<GpuReading>, DcgmError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let cols: Vec<&str> = trimmed.split(',').map(str::trim).collect();
    if cols.len() != 6 {
        return Err(DcgmError::Parse {
            line: line.to_string(),
            reason: format!("expected 6 CSV columns, got {}", cols.len()),
        });
    }
    let index = cols[0].parse::<u32>().map_err(|e| DcgmError::Parse {
        line: line.to_string(),
        reason: format!("index {:?} not u32: {e}", cols[0]),
    })?;
    let utilization_pct = parse_f32_field(line, "utilization.gpu", cols[1])?;
    if !(0.0..=100.0).contains(&utilization_pct) {
        return Err(DcgmError::Parse {
            line: line.to_string(),
            reason: format!("utilization {utilization_pct} outside 0.0..=100.0"),
        });
    }
    let vram_used_mib = cols[2].parse::<u64>().map_err(|e| DcgmError::Parse {
        line: line.to_string(),
        reason: format!("memory.used {:?} not u64: {e}", cols[2]),
    })?;
    let vram_total_mib = cols[3].parse::<u64>().map_err(|e| DcgmError::Parse {
        line: line.to_string(),
        reason: format!("memory.total {:?} not u64: {e}", cols[3]),
    })?;
    let temperature_c = parse_f32_field(line, "temperature.gpu", cols[4])?;
    let power_w = parse_f32_field(line, "power.draw", cols[5])?;
    Ok(Some(GpuReading {
        index,
        utilization: utilization_pct / 100.0,
        vram_used_mib,
        vram_total_mib,
        temperature_c,
        power_w,
    }))
}

fn parse_f32_field(line: &str, field: &str, value: &str) -> Result<f32, DcgmError> {
    value.parse::<f32>().map_err(|e| DcgmError::Parse {
        line: line.to_string(),
        reason: format!("{field} {value:?} not f32: {e}"),
    })
}

/// Parse the full stdout of `nvidia-smi` (multiple GPU rows) into a
/// `Vec<GpuReading>` ordered as the kernel returned them. Blank
/// lines are skipped.
///
/// # Errors
///
/// Returns `DcgmError::Parse` if any row fails, or
/// `DcgmError::Unavailable` if no rows were observed (driver
/// up but zero GPUs present).
pub fn parse_nvidia_smi_csv(stdout: &str) -> Result<Vec<GpuReading>, DcgmError> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        if let Some(reading) = parse_nvidia_smi_line(line)? {
            out.push(reading);
        }
    }
    if out.is_empty() {
        return Err(DcgmError::Unavailable(
            "nvidia-smi returned no GPU rows".to_string(),
        ));
    }
    Ok(out)
}

/// Combine a parsed GPU list + `DcgmGpuIndices` into a `DcgmReading`.
/// Splits the named blackwell + gpu3090 entries off into their own
/// fields and collects everything else into `others`.
///
/// # Errors
///
/// Returns `DcgmError::GpuMissing` if either named index is absent.
pub fn assemble_dcgm_reading(
    gpus: Vec<GpuReading>,
    indices: DcgmGpuIndices,
    captured_at_unix_micros: u128,
) -> Result<DcgmReading, DcgmError> {
    let mut blackwell: Option<GpuReading> = None;
    let mut gpu3090: Option<GpuReading> = None;
    let mut others = Vec::new();
    let observed: Vec<u32> = gpus.iter().map(|g| g.index).collect();
    for gpu in gpus {
        if gpu.index == indices.blackwell {
            blackwell = Some(gpu);
        } else if gpu.index == indices.gpu3090 {
            gpu3090 = Some(gpu);
        } else {
            others.push(gpu);
        }
    }
    let blackwell = blackwell.ok_or_else(|| DcgmError::GpuMissing {
        index: indices.blackwell,
        observed: observed.clone(),
    })?;
    let gpu3090 = gpu3090.ok_or(DcgmError::GpuMissing {
        index: indices.gpu3090,
        observed,
    })?;
    Ok(DcgmReading {
        captured_at_unix_micros,
        indices,
        blackwell,
        gpu3090,
        others,
    })
}

// ============================================================================
// DcgmSource trait
// ============================================================================

/// Effector-style stubbable boundary between the scheduler and the
/// GPU pressure substrate. The scheduler calls `read()` once per
/// sample tick and routes the resulting `DcgmReading` into a
/// [`crate::ResourceMeasurements`].
pub trait DcgmSource: Send + Sync {
    /// Take a snapshot of all configured GPUs.
    ///
    /// # Errors
    ///
    /// Returns `DcgmError::Unavailable` if substrate is absent
    /// (honest-offline); `DcgmError::CommandIo` / `CommandExit` on
    /// subprocess failure; `DcgmError::Parse` on kernel-format
    /// drift; `DcgmError::GpuMissing` on index misconfiguration.
    fn read(&self) -> Result<DcgmReading, DcgmError>;
}

// ============================================================================
// NvidiaSmiDcgmSource (real-substrate impl)
// ============================================================================

/// Real-substrate `DcgmSource` invoking `nvidia-smi` as a
/// subprocess. Honest-offline: if `nvidia-smi` is not on PATH,
/// exits non-zero, or no GPUs are visible, `read()` returns
/// `DcgmError::Unavailable`.
#[derive(Debug, Clone)]
pub struct NvidiaSmiDcgmSource {
    command: PathBuf,
    indices: DcgmGpuIndices,
}

impl NvidiaSmiDcgmSource {
    /// Construct with the default `nvidia-smi` binary (PATH lookup)
    /// and the sain-01 GPU index baseline.
    #[must_use]
    pub fn new() -> Self {
        Self {
            command: PathBuf::from(DEFAULT_NVIDIA_SMI_BIN),
            indices: DcgmGpuIndices::sain01_baseline(),
        }
    }

    /// Override the `nvidia-smi` binary path. Used by the test
    /// suite which writes a shell-script fixture to `tempfile`.
    #[must_use]
    pub fn with_command_path(mut self, command: impl Into<PathBuf>) -> Self {
        self.command = command.into();
        self
    }

    /// Override the GPU index mapping for non-sain-01 topologies.
    #[must_use]
    pub fn with_indices(mut self, indices: DcgmGpuIndices) -> Self {
        self.indices = indices;
        self
    }

    /// Borrow the nvidia-smi command path.
    #[must_use]
    pub fn command(&self) -> &Path {
        &self.command
    }

    /// Borrow the GPU indices.
    #[must_use]
    pub fn indices(&self) -> &DcgmGpuIndices {
        &self.indices
    }

    /// Exec `nvidia-smi` with a bounded retry on `ETXTBSY`
    /// (`ExecutableFileBusy`).
    ///
    /// `execve` returns `ETXTBSY` ("Text file busy") when the target
    /// binary is open for writing by some process at exec time. This is
    /// transient and clears on its own: on a busy host another process
    /// may briefly hold the binary (e.g. a package manager rewriting it
    /// during an upgrade), and under this crate's own parallel test run
    /// a sibling thread's fork+exec can momentarily hold a write handle
    /// to the just-written fixture script. A short bounded retry with a
    /// small linear backoff clears it without masking a genuine failure:
    /// every other error kind (including `NotFound`) returns immediately,
    /// and the attempt budget is small enough that a truly stuck binary
    /// still fails fast (~0.3s worst case) rather than hanging.
    fn run_nvidia_smi(&self) -> Result<std::process::Output, DcgmError> {
        const MAX_ATTEMPTS: u32 = 5;
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            match Command::new(&self.command)
                .arg(format!("--query-gpu={NVIDIA_SMI_QUERY}"))
                .arg(format!("--format={NVIDIA_SMI_FORMAT}"))
                .output()
            {
                Ok(output) => return Ok(output),
                Err(e)
                    if e.kind() == std::io::ErrorKind::ExecutableFileBusy
                        && attempt < MAX_ATTEMPTS =>
                {
                    // Linear backoff: 20ms, 40ms, 60ms, 80ms.
                    std::thread::sleep(std::time::Duration::from_millis(20 * u64::from(attempt)));
                }
                Err(e) => {
                    return Err(match e.kind() {
                        std::io::ErrorKind::NotFound => DcgmError::Unavailable(format!(
                            "{} not found on PATH",
                            self.command.display()
                        )),
                        _ => DcgmError::CommandIo(e),
                    });
                }
            }
        }
    }
}

impl Default for NvidiaSmiDcgmSource {
    fn default() -> Self {
        Self::new()
    }
}

impl DcgmSource for NvidiaSmiDcgmSource {
    fn read(&self) -> Result<DcgmReading, DcgmError> {
        let output = self.run_nvidia_smi()?;
        if !output.status.success() {
            let stderr_full = String::from_utf8_lossy(&output.stderr);
            let stderr = if stderr_full.len() > 1024 {
                stderr_full.chars().take(1024).collect()
            } else {
                stderr_full.into_owned()
            };
            // Common kernel-driver-missing pattern: nvidia-smi prints
            // "NVIDIA-SMI has failed because it couldn't communicate
            // with the NVIDIA driver" and exits 9. Treat as honest-
            // offline rather than command-broken.
            if stderr.contains("couldn't communicate with the NVIDIA driver")
                || stderr.contains("NVIDIA driver is not loaded")
            {
                return Err(DcgmError::Unavailable(format!(
                    "nvidia driver not loaded: {stderr}"
                )));
            }
            return Err(DcgmError::CommandExit {
                code: output.status.code().unwrap_or(-1),
                stderr,
            });
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let gpus = parse_nvidia_smi_csv(&stdout)?;
        let captured_at_unix_micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros())
            .unwrap_or(0);
        assemble_dcgm_reading(gpus, self.indices, captured_at_unix_micros)
    }
}

// ============================================================================
// MockDcgmSource (test injector)
// ============================================================================

/// In-memory `DcgmSource` for tests. Returns a fixed `DcgmReading`
/// constructed via `with_blackwell_*` / `with_gpu3090_*`.
#[derive(Debug, Clone)]
pub struct MockDcgmSource {
    blackwell: GpuReading,
    gpu3090: GpuReading,
    others: Vec<GpuReading>,
    indices: DcgmGpuIndices,
    fail_with: Option<MockFailureMode>,
}

#[derive(Debug, Clone, PartialEq)]
enum MockFailureMode {
    Unavailable,
    GpuMissing(u32),
}

impl MockDcgmSource {
    /// All-clean source — Blackwell + 3090 both report 0% / 0 MiB.
    #[must_use]
    pub fn clean() -> Self {
        let indices = DcgmGpuIndices::sain01_baseline();
        Self {
            blackwell: GpuReading::clean(indices.blackwell),
            gpu3090: GpuReading::clean(indices.gpu3090),
            others: Vec::new(),
            indices,
            fail_with: None,
        }
    }

    /// Set Blackwell VRAM usage in MiB (out of `vram_total_mib`).
    /// If `total` is 0 it's set to a realistic Blackwell figure
    /// (24576 MiB / 24 GiB) so `vram_util_fraction()` is meaningful.
    #[must_use]
    pub fn with_blackwell_vram(mut self, used_mib: u64, total_mib: u64) -> Self {
        self.blackwell.vram_used_mib = used_mib;
        self.blackwell.vram_total_mib = if total_mib == 0 { 24576 } else { total_mib };
        self
    }

    /// Set Blackwell compute utilization (0.0–1.0).
    #[must_use]
    pub fn with_blackwell_util(mut self, util: f32) -> Self {
        self.blackwell.utilization = util;
        self
    }

    /// Set 3090 compute utilization (0.0–1.0).
    #[must_use]
    pub fn with_gpu3090_util(mut self, util: f32) -> Self {
        self.gpu3090.utilization = util;
        self
    }

    /// Set 3090 VRAM usage in MiB (default total 24576).
    #[must_use]
    pub fn with_gpu3090_vram(mut self, used_mib: u64, total_mib: u64) -> Self {
        self.gpu3090.vram_used_mib = used_mib;
        self.gpu3090.vram_total_mib = if total_mib == 0 { 24576 } else { total_mib };
        self
    }

    /// Make `read()` return `PsiError::Unavailable` — simulates
    /// honest-offline (driver missing).
    #[must_use]
    pub fn unavailable() -> Self {
        let mut s = Self::clean();
        s.fail_with = Some(MockFailureMode::Unavailable);
        s
    }

    /// Simulate misconfigured indices — a configured GPU is missing
    /// from the observation.
    #[must_use]
    pub fn gpu_missing(index: u32) -> Self {
        let mut s = Self::clean();
        s.fail_with = Some(MockFailureMode::GpuMissing(index));
        s
    }
}

impl DcgmSource for MockDcgmSource {
    fn read(&self) -> Result<DcgmReading, DcgmError> {
        match &self.fail_with {
            Some(MockFailureMode::Unavailable) => {
                Err(DcgmError::Unavailable("mock unavailable".to_string()))
            }
            Some(MockFailureMode::GpuMissing(index)) => Err(DcgmError::GpuMissing {
                index: *index,
                observed: vec![],
            }),
            None => Ok(DcgmReading {
                captured_at_unix_micros: 0,
                indices: self.indices,
                blackwell: self.blackwell,
                gpu3090: self.gpu3090,
                others: self.others.clone(),
            }),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // ---------------- parse_nvidia_smi_line -------------------------------

    #[test]
    fn parses_canonical_row() {
        let line = "0, 35, 22000, 24576, 67, 220.5";
        let r = parse_nvidia_smi_line(line).unwrap().unwrap();
        assert_eq!(r.index, 0);
        assert!((r.utilization - 0.35).abs() < 1e-5);
        assert_eq!(r.vram_used_mib, 22000);
        assert_eq!(r.vram_total_mib, 24576);
        assert!((r.temperature_c - 67.0).abs() < 1e-5);
        assert!((r.power_w - 220.5).abs() < 1e-5);
    }

    #[test]
    fn parses_zero_utilization_idle_card() {
        let line = "1, 0, 100, 24576, 35, 10.0";
        let r = parse_nvidia_smi_line(line).unwrap().unwrap();
        assert_eq!(r.utilization, 0.0);
    }

    #[test]
    fn empty_line_returns_none() {
        assert!(parse_nvidia_smi_line("").unwrap().is_none());
        assert!(parse_nvidia_smi_line("   \t  ").unwrap().is_none());
    }

    #[test]
    fn wrong_column_count_rejected() {
        let err = parse_nvidia_smi_line("0, 35, 22000").unwrap_err();
        let DcgmError::Parse { reason, .. } = err else {
            panic!("expected Parse")
        };
        assert!(reason.contains("6 CSV columns"));
    }

    #[test]
    fn non_numeric_index_rejected() {
        let err = parse_nvidia_smi_line("abc, 35, 22000, 24576, 67, 220").unwrap_err();
        assert!(matches!(err, DcgmError::Parse { .. }));
    }

    #[test]
    fn out_of_range_utilization_rejected() {
        let err = parse_nvidia_smi_line("0, 150, 22000, 24576, 67, 220").unwrap_err();
        let DcgmError::Parse { reason, .. } = err else {
            panic!("expected Parse")
        };
        assert!(reason.contains("outside"));
    }

    // ---------------- parse_nvidia_smi_csv --------------------------------

    #[test]
    fn parses_two_gpu_stdout() {
        let stdout = "\
0, 50, 22000, 24576, 70, 250.0
1, 30, 8000, 24576, 65, 180.0
";
        let gpus = parse_nvidia_smi_csv(stdout).unwrap();
        assert_eq!(gpus.len(), 2);
        assert_eq!(gpus[0].index, 0);
        assert_eq!(gpus[1].index, 1);
    }

    #[test]
    fn empty_stdout_returns_unavailable() {
        let err = parse_nvidia_smi_csv("").unwrap_err();
        assert!(matches!(err, DcgmError::Unavailable(_)));
    }

    #[test]
    fn whitespace_only_returns_unavailable() {
        let err = parse_nvidia_smi_csv("\n\n   \n").unwrap_err();
        assert!(matches!(err, DcgmError::Unavailable(_)));
    }

    #[test]
    fn parse_error_propagates_with_offending_line() {
        let stdout = "\
0, 50, 22000, 24576, 70, 250.0
garbage row
1, 30, 8000, 24576, 65, 180.0
";
        let err = parse_nvidia_smi_csv(stdout).unwrap_err();
        let DcgmError::Parse { line, .. } = err else {
            panic!("expected Parse")
        };
        assert_eq!(line.trim(), "garbage row");
    }

    // ---------------- assemble_dcgm_reading -------------------------------

    #[test]
    fn assemble_baseline_two_gpus() {
        let gpus = vec![
            GpuReading {
                index: 0,
                utilization: 0.5,
                vram_used_mib: 22000,
                vram_total_mib: 24576,
                temperature_c: 70.0,
                power_w: 250.0,
            },
            GpuReading {
                index: 1,
                utilization: 0.3,
                vram_used_mib: 8000,
                vram_total_mib: 24576,
                temperature_c: 65.0,
                power_w: 180.0,
            },
        ];
        let reading =
            assemble_dcgm_reading(gpus, DcgmGpuIndices::sain01_baseline(), 1_000_000).unwrap();
        assert_eq!(reading.blackwell.index, 0);
        assert_eq!(reading.gpu3090.index, 1);
        assert!(reading.others.is_empty());
        assert!((reading.blackwell_vram_util() - 22000.0 / 24576.0).abs() < 1e-4);
        assert!((reading.gpu3090_util() - 0.3).abs() < 1e-5);
    }

    #[test]
    fn assemble_with_third_gpu_lands_in_others() {
        let gpus = vec![
            GpuReading::clean(0),
            GpuReading::clean(1),
            GpuReading::clean(2),
        ];
        let reading = assemble_dcgm_reading(gpus, DcgmGpuIndices::sain01_baseline(), 0).unwrap();
        assert_eq!(reading.others.len(), 1);
        assert_eq!(reading.others[0].index, 2);
    }

    #[test]
    fn assemble_missing_blackwell_index_rejected() {
        let gpus = vec![GpuReading::clean(1), GpuReading::clean(2)];
        let err = assemble_dcgm_reading(gpus, DcgmGpuIndices::sain01_baseline(), 0).unwrap_err();
        let DcgmError::GpuMissing { index, observed } = err else {
            panic!("expected GpuMissing")
        };
        assert_eq!(index, 0);
        assert_eq!(observed, vec![1, 2]);
    }

    #[test]
    fn assemble_missing_gpu3090_index_rejected() {
        let gpus = vec![GpuReading::clean(0)];
        let err = assemble_dcgm_reading(gpus, DcgmGpuIndices::sain01_baseline(), 0).unwrap_err();
        let DcgmError::GpuMissing { index, .. } = err else {
            panic!("expected GpuMissing")
        };
        assert_eq!(index, 1);
    }

    #[test]
    fn assemble_with_custom_indices() {
        let gpus = vec![GpuReading::clean(2), GpuReading::clean(5)];
        let reading = assemble_dcgm_reading(gpus, DcgmGpuIndices::custom(5, 2), 0).unwrap();
        assert_eq!(reading.blackwell.index, 5);
        assert_eq!(reading.gpu3090.index, 2);
    }

    // ---------------- GpuReading accessors --------------------------------

    #[test]
    fn vram_util_fraction_zero_total_returns_zero() {
        let r = GpuReading::clean(0);
        assert_eq!(r.vram_util_fraction(), 0.0);
    }

    #[test]
    fn vram_util_fraction_realistic() {
        let r = GpuReading {
            index: 0,
            utilization: 0.0,
            vram_used_mib: 22000,
            vram_total_mib: 24576,
            temperature_c: 0.0,
            power_w: 0.0,
        };
        // 22000 / 24576 ≈ 0.8952
        assert!((r.vram_util_fraction() - 0.8952).abs() < 0.001);
    }

    // ---------------- NvidiaSmiDcgmSource (with shell fixtures) -----------

    #[cfg(unix)]
    fn write_fixture_script(dir: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn nvidia_smi_real_substrate_success() {
        let tmp = tempdir().unwrap();
        let script = write_fixture_script(
            tmp.path(),
            "nvidia-smi-ok",
            "#!/bin/sh\ncat <<'EOF'\n0, 45, 22000, 24576, 70, 250.0\n1, 30, 8000, 24576, 65, 180.0\nEOF\n",
        );
        let src = NvidiaSmiDcgmSource::new().with_command_path(&script);
        let reading = src.read().unwrap();
        assert_eq!(reading.blackwell.index, 0);
        assert_eq!(reading.gpu3090.index, 1);
        assert!((reading.gpu3090_util() - 0.3).abs() < 1e-5);
    }

    /// Regression guard for the `ETXTBSY` bounded retry in
    /// `run_nvidia_smi`. Holding the fixture script open for writing
    /// makes `execve` return `ETXTBSY`; a background thread releases the
    /// handle mid-retry so the bounded retry inside `read()` succeeds.
    /// Note: if a given kernel/filesystem does not raise `ETXTBSY` here,
    /// `read()` simply succeeds on the first attempt — the test still
    /// passes (it is a best-effort exercise of the retry path, never a
    /// flake in the other direction). This is the exact failure mode
    /// that flaked `nvidia_smi_real_substrate_success` in CI.
    #[cfg(unix)]
    #[test]
    fn nvidia_smi_retries_through_transient_etxtbsy() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let tmp = tempdir().unwrap();
        let script = write_fixture_script(
            tmp.path(),
            "nvidia-smi-busy",
            "#!/bin/sh\ncat <<'EOF'\n0, 45, 22000, 24576, 70, 250.0\n1, 30, 8000, 24576, 65, 180.0\nEOF\n",
        );

        // Open for writing → file is "busy" for execve while live.
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&script)
            .unwrap();
        let released = Arc::new(AtomicBool::new(false));
        let released_bg = Arc::clone(&released);
        let releaser = std::thread::spawn(move || {
            // Release well within the retry budget (20+40+60+80ms).
            std::thread::sleep(std::time::Duration::from_millis(50));
            drop(writer);
            released_bg.store(true, Ordering::SeqCst);
        });

        let src = NvidiaSmiDcgmSource::new().with_command_path(&script);
        let reading = src.read().unwrap();
        releaser.join().unwrap();
        assert!(released.load(Ordering::SeqCst));
        assert_eq!(reading.blackwell.index, 0);
        assert_eq!(reading.gpu3090.index, 1);
    }

    #[cfg(unix)]
    #[test]
    fn nvidia_smi_command_not_found_returns_unavailable() {
        let tmp = tempdir().unwrap();
        let nonexistent = tmp.path().join("never-created-nvidia-smi");
        let src = NvidiaSmiDcgmSource::new().with_command_path(&nonexistent);
        let err = src.read().unwrap_err();
        assert!(matches!(err, DcgmError::Unavailable(_)));
    }

    #[cfg(unix)]
    #[test]
    fn nvidia_smi_driver_missing_returns_unavailable() {
        let tmp = tempdir().unwrap();
        let script = write_fixture_script(
            tmp.path(),
            "nvidia-smi-driver-missing",
            "#!/bin/sh\necho \"NVIDIA-SMI has failed because it couldn't communicate with the NVIDIA driver. Make sure the driver is installed and loaded.\" >&2\nexit 9\n",
        );
        let src = NvidiaSmiDcgmSource::new().with_command_path(&script);
        let err = src.read().unwrap_err();
        assert!(
            matches!(err, DcgmError::Unavailable(_)),
            "expected Unavailable, got {err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn nvidia_smi_non_zero_other_error_returns_command_exit() {
        let tmp = tempdir().unwrap();
        let script = write_fixture_script(
            tmp.path(),
            "nvidia-smi-fail",
            "#!/bin/sh\necho \"some other unexpected error\" >&2\nexit 2\n",
        );
        let src = NvidiaSmiDcgmSource::new().with_command_path(&script);
        let err = src.read().unwrap_err();
        assert!(matches!(err, DcgmError::CommandExit { code: 2, .. }));
    }

    #[cfg(unix)]
    #[test]
    fn nvidia_smi_returns_no_gpus_yields_unavailable() {
        let tmp = tempdir().unwrap();
        let script = write_fixture_script(tmp.path(), "nvidia-smi-empty", "#!/bin/sh\nexit 0\n");
        let src = NvidiaSmiDcgmSource::new().with_command_path(&script);
        let err = src.read().unwrap_err();
        assert!(matches!(err, DcgmError::Unavailable(_)));
    }

    // ---------------- MockDcgmSource --------------------------------------

    #[test]
    fn mock_clean_returns_zeros() {
        let src = MockDcgmSource::clean();
        let r = src.read().unwrap();
        assert_eq!(r.blackwell_vram_util(), 0.0);
        assert_eq!(r.gpu3090_util(), 0.0);
    }

    #[test]
    fn mock_with_blackwell_vram_and_util() {
        let src = MockDcgmSource::clean()
            .with_blackwell_vram(22000, 24576)
            .with_blackwell_util(0.8);
        let r = src.read().unwrap();
        assert!((r.blackwell_vram_util() - 22000.0 / 24576.0).abs() < 1e-4);
        assert_eq!(r.blackwell.utilization, 0.8);
    }

    #[test]
    fn mock_unavailable_returns_unavailable() {
        let src = MockDcgmSource::unavailable();
        let err = src.read().unwrap_err();
        assert!(matches!(err, DcgmError::Unavailable(_)));
    }

    #[test]
    fn mock_gpu_missing_returns_gpu_missing() {
        let src = MockDcgmSource::gpu_missing(0);
        let err = src.read().unwrap_err();
        let DcgmError::GpuMissing { index, .. } = err else {
            panic!("expected GpuMissing")
        };
        assert_eq!(index, 0);
    }

    // ---------------- Trait object dispatch -------------------------------

    #[test]
    fn trait_object_dispatch_works() {
        let sources: Vec<Box<dyn DcgmSource>> = vec![
            Box::new(
                MockDcgmSource::clean()
                    .with_blackwell_vram(12288, 24576)
                    .with_blackwell_util(0.5),
            ),
            Box::new(MockDcgmSource::unavailable()),
        ];
        let r1 = sources[0].read().unwrap();
        assert!((r1.blackwell_vram_util() - 0.5).abs() < 1e-4);
        let err = sources[1].read().unwrap_err();
        assert!(matches!(err, DcgmError::Unavailable(_)));
    }

    // ---------------- DcgmGpuIndices --------------------------------------

    #[test]
    fn indices_default_is_sain01_baseline() {
        let idx: DcgmGpuIndices = Default::default();
        assert_eq!(idx, DcgmGpuIndices::sain01_baseline());
        assert_eq!(idx.blackwell, 0);
        assert_eq!(idx.gpu3090, 1);
    }

    #[test]
    fn indices_custom_constructor() {
        let idx = DcgmGpuIndices::custom(2, 5);
        assert_eq!(idx.blackwell, 2);
        assert_eq!(idx.gpu3090, 5);
    }
}
