//! `selfdef-scheduler::psi` — M01156: Linux PSI (Pressure Stall Information)
//! source bridge for the Goldilocks Scheduler backpressure surface.
//!
//! Dump grounding (avx-plus-plus 2026-05-18 line 18197):
//! > *"Linux PSI + DCGM + trace metrics feed the scheduler"*
//!
//! Catalog grounding: MS048 module `M01156 selfdef-scheduler-psi-source
//! (Linux /proc/pressure/*)` per `~/selfdef/backlog/milestones/
//! MS048-goldilocks-scheduler-hardware-aware-resource-routing.md`.
//!
//! Doctrinal anchor: [Peace Machine + Core Law](https://github.com/
//! cyberpunk042/devops-solutions-information-hub/blob/main/wiki/spine/
//! doctrine/peace-machine-and-core-law.md) — Core Law clause
//! "Runtime routes" + peace-machine clause "disciplined enough to
//! explain itself" (every PSI reading is timestamped + auditable).
//!
//! ## What this module provides
//!
//! 1. `PsiReading` — a single timestamped snapshot of the
//!    three Linux PSI domains (cpu / memory / io) at the kernel's
//!    `avg10` / `avg60` / `avg300` / `total` granularity.
//! 2. `PsiSource` trait — the Effector-style stubbable boundary the
//!    scheduler's `BackpressureMonitor` calls into to obtain
//!    `cpu_psi` / `mem_psi` / `io_psi` for `ResourceMeasurements`.
//!    Trait shape per the existing
//!    `selfdef_scheduler` crate doc comment "PsiSource / DcgmSource /
//!    HumanGateSource — Effector-style traits stubbable for testing
//!    (real-source bridges land in D7+)".
//! 3. `parse_psi_line` — parser for the kernel's
//!    `/proc/pressure/<resource>` format:
//!    `some avg10=0.00 avg60=0.00 avg300=0.00 total=0`
//!    (and the optional `full avg10=... total=...` line for memory
//!    and io which CPU does not emit).
//! 4. `ProcfsPsiSource` — real-substrate impl reading
//!    `/proc/pressure/{cpu,memory,io}`. Honest-offline: if any
//!    `/proc/pressure/<resource>` is absent (kernel < 4.20, PSI
//!    config off, container without PSI exposure) the reader returns
//!    `PsiError::Unavailable` rather than fabricating a zero.
//! 5. `MockPsiSource` — test injector with `with_cpu` /
//!    `with_mem` / `with_io` constructors so unit tests can
//!    drive the `BackpressureMonitor` without `/proc` substrate.
//! 6. `PsiError` — typed error surface (`Io` / `Parse` /
//!    `Unavailable`) so callers can distinguish substrate-absent
//!    from substrate-broken.
//!
//! ## Non-goals
//!
//! - Not a histogram aggregator. The kernel's `total=<u64>` counter is
//!   surfaced but per-window aggregation lives in the
//!   `BackpressureMonitor` (hysteresis + 10s exit window per
//!   R11357 — already implemented in `lib.rs`).
//! - Not a metric sink. PSI readings are returned to the caller;
//!   Prometheus / OCSF emission lives in `M01168` (prometheus
//!   exporter) and `M01169` (OCSF emitter) — separate slots.
//! - Not a watchdog. Polling cadence is decided by the
//!   `Scheduler::observe` driver loop, not by this module.
//!
//! Standing rule: We do not minimize anything.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default mount path for the kernel PSI cgroup-root directory.
pub const PROCFS_PRESSURE_DIR: &str = "/proc/pressure";

/// Default sampling line — the kernel emits `some` for cpu/memory/io
/// and additionally `full` for memory + io. The `some avg10` value
/// matches the [`crate::BackpressureThresholds`] `cpu_pressure`,
/// `ram_pressure`, `io_pressure` semantics (R11340-R11346).
pub const KIND_SOME: &str = "some";

/// Optional second-line kind emitted by the kernel for memory + io
/// pressure (not emitted for cpu). Indicates ALL tasks were stalled
/// (full stall) vs `some` which means at least one task stalled.
pub const KIND_FULL: &str = "full";

// ============================================================================
// PsiKind + PsiBucket + PsiReading
// ============================================================================

/// Which kernel-emitted line a bucket originated from. Mirrors the
/// kernel's `/proc/pressure/<resource>` format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PsiKind {
    /// At least one runnable task stalled. Always present.
    Some,
    /// All runnable tasks stalled. Present for memory + io, absent
    /// for cpu (kernel never emits cpu `full`).
    Full,
}

impl PsiKind {
    /// Parse the leading kind token of a kernel PSI line.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "some" => Some(Self::Some),
            "full" => Some(Self::Full),
            _ => None,
        }
    }
}

/// One time-window bucket from a `/proc/pressure/<r>` line.
/// Fractions are 0.0–1.0 (kernel emits 0.00–100.00 percent;
/// the parser divides by 100).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PsiBucket {
    /// `avg10` — 10-second exponentially-decayed average. This is
    /// the field `BackpressureThresholds` matches per R11340-R11346.
    pub avg10: f32,
    /// `avg60` — 60-second exponentially-decayed average.
    pub avg60: f32,
    /// `avg300` — 300-second exponentially-decayed average.
    pub avg300: f32,
    /// `total=<u64>` microseconds spent stalled since boot. Monotonic
    /// counter; deltas can be derived between samples.
    pub total_micros: u64,
}

impl PsiBucket {
    /// All-clean bucket.
    #[must_use]
    pub const fn clean() -> Self {
        Self {
            avg10: 0.0,
            avg60: 0.0,
            avg300: 0.0,
            total_micros: 0,
        }
    }
}

/// One full reading of a `/proc/pressure/<resource>` file — the
/// `some` bucket (always present) plus the optional `full` bucket
/// (memory + io only). For cpu, `full` is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PsiResourceReading {
    /// `some` bucket.
    pub some: PsiBucket,
    /// `full` bucket — `None` for cpu, `Some` for memory + io.
    pub full: Option<PsiBucket>,
}

impl PsiResourceReading {
    /// All-clean reading (e.g., test fixture or honest-offline marker).
    #[must_use]
    pub const fn clean(emit_full: bool) -> Self {
        Self {
            some: PsiBucket::clean(),
            full: if emit_full { Some(PsiBucket::clean()) } else { None },
        }
    }
}

/// Triple of `/proc/pressure/{cpu,memory,io}` readings sampled at
/// a single instant (`captured_at_unix_micros`). The scheduler's
/// `BackpressureMonitor` consumes the `.some.avg10` from each
/// resource as the `cpu_psi` / `mem_psi` / `io_psi` field of
/// [`crate::ResourceMeasurements`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PsiReading {
    /// Wall-clock unix microseconds when the sample was taken.
    pub captured_at_unix_micros: u128,
    /// CPU PSI reading (`some` only — cpu never emits `full`).
    pub cpu: PsiResourceReading,
    /// Memory PSI reading (`some` + `full`).
    pub memory: PsiResourceReading,
    /// IO PSI reading (`some` + `full`).
    pub io: PsiResourceReading,
}

impl PsiReading {
    /// Convenience accessor — the `some.avg10` value of the cpu domain,
    /// as a fraction in 0.0–1.0. Matches the `cpu_psi` field of
    /// [`crate::ResourceMeasurements`].
    #[must_use]
    pub fn cpu_some_avg10(&self) -> f32 {
        self.cpu.some.avg10
    }

    /// Convenience accessor — the `some.avg10` value of the memory
    /// domain. Matches the `mem_psi` field of
    /// [`crate::ResourceMeasurements`].
    #[must_use]
    pub fn mem_some_avg10(&self) -> f32 {
        self.memory.some.avg10
    }

    /// Convenience accessor — the `some.avg10` value of the io domain.
    /// Matches the `io_psi` field of [`crate::ResourceMeasurements`].
    #[must_use]
    pub fn io_some_avg10(&self) -> f32 {
        self.io.some.avg10
    }
}

// ============================================================================
// PsiError
// ============================================================================

/// Errors emitted by [`PsiSource`] implementations.
#[derive(Debug, Error)]
pub enum PsiError {
    /// `/proc/pressure/<resource>` file IO failed (read / open / etc.).
    #[error("psi io ({resource}): {source}")]
    Io {
        /// Which resource the IO error came from (cpu / memory / io).
        resource: &'static str,
        /// Underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// PSI line failed to parse (kernel format drift, partial line).
    #[error("psi parse ({resource}): line {line:?}: {reason}")]
    Parse {
        /// Resource being parsed.
        resource: &'static str,
        /// Raw line that failed.
        line: String,
        /// Human reason (e.g. "missing avg10 field").
        reason: String,
    },
    /// `/proc/pressure/` not present (kernel < 4.20, CONFIG_PSI off,
    /// container without PSI exposure). Honest-offline marker — caller
    /// surfaces a `state_dir_present=0` gauge or equivalent.
    #[error("psi unavailable: {0}")]
    Unavailable(String),
}

// ============================================================================
// Parser
// ============================================================================

/// Parse one kernel PSI line into a `(PsiKind, PsiBucket)` pair.
///
/// Expected format (kernel docs / `psi.c`):
///
/// ```text
/// some avg10=0.00 avg60=0.00 avg300=0.00 total=0
/// full avg10=0.00 avg60=0.00 avg300=0.00 total=0
/// ```
///
/// The function is strict on field presence (all four `avg10` /
/// `avg60` / `avg300` / `total` must be present) but tolerant of
/// extra whitespace + trailing newlines + ordering perturbations
/// within the four key=value pairs.
///
/// Returns `None` if the line is empty or whitespace-only (so
/// callers can iterate file lines without dispatching on empty).
/// Returns `Err` on malformed kind / missing field / non-numeric
/// value.
///
/// # Errors
///
/// Returns `PsiError::Parse` with `resource` set to the caller-
/// supplied `resource` tag (`"cpu"` / `"memory"` / `"io"`).
pub fn parse_psi_line(
    resource: &'static str,
    line: &str,
) -> Result<Option<(PsiKind, PsiBucket)>, PsiError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let mut parts = trimmed.split_whitespace();
    let Some(kind_str) = parts.next() else {
        return Err(PsiError::Parse {
            resource,
            line: line.to_string(),
            reason: "empty line (missing kind token)".to_string(),
        });
    };
    let Some(kind) = PsiKind::parse(kind_str) else {
        return Err(PsiError::Parse {
            resource,
            line: line.to_string(),
            reason: format!("unknown kind {kind_str:?}; expected 'some' or 'full'"),
        });
    };
    let mut avg10: Option<f32> = None;
    let mut avg60: Option<f32> = None;
    let mut avg300: Option<f32> = None;
    let mut total: Option<u64> = None;
    for token in parts {
        let Some((k, v)) = token.split_once('=') else {
            return Err(PsiError::Parse {
                resource,
                line: line.to_string(),
                reason: format!("token {token:?} missing '='"),
            });
        };
        match k {
            "avg10" => {
                avg10 = Some(parse_avg_percent(resource, line, v)?);
            }
            "avg60" => {
                avg60 = Some(parse_avg_percent(resource, line, v)?);
            }
            "avg300" => {
                avg300 = Some(parse_avg_percent(resource, line, v)?);
            }
            "total" => {
                total = Some(v.parse::<u64>().map_err(|e| PsiError::Parse {
                    resource,
                    line: line.to_string(),
                    reason: format!("total={v:?} not u64: {e}"),
                })?);
            }
            other => {
                // Kernel might add new fields in the future. We accept
                // unknown trailing key=value pairs rather than fail —
                // the four canonical fields are still required.
                let _ = other;
            }
        }
    }
    let (Some(avg10), Some(avg60), Some(avg300), Some(total)) = (avg10, avg60, avg300, total)
    else {
        return Err(PsiError::Parse {
            resource,
            line: line.to_string(),
            reason: "missing one of avg10 / avg60 / avg300 / total".to_string(),
        });
    };
    Ok(Some((
        kind,
        PsiBucket {
            avg10,
            avg60,
            avg300,
            total_micros: total,
        },
    )))
}

fn parse_avg_percent(
    resource: &'static str,
    line: &str,
    value: &str,
) -> Result<f32, PsiError> {
    let pct: f32 = value.parse().map_err(|e| PsiError::Parse {
        resource,
        line: line.to_string(),
        reason: format!("avg value {value:?} not f32: {e}"),
    })?;
    if !(0.0..=100.0).contains(&pct) {
        return Err(PsiError::Parse {
            resource,
            line: line.to_string(),
            reason: format!("avg value {pct} outside 0.0..=100.0"),
        });
    }
    Ok(pct / 100.0)
}

/// Parse the full contents of one `/proc/pressure/<resource>` file
/// into a `PsiResourceReading`. The `some` line is required; the
/// `full` line is optional (cpu doesn't emit it).
///
/// # Errors
///
/// Returns `PsiError::Parse` if the `some` line is missing or any
/// line fails to parse.
pub fn parse_psi_file_contents(
    resource: &'static str,
    contents: &str,
) -> Result<PsiResourceReading, PsiError> {
    let mut some: Option<PsiBucket> = None;
    let mut full: Option<PsiBucket> = None;
    for line in contents.lines() {
        let Some((kind, bucket)) = parse_psi_line(resource, line)? else {
            continue;
        };
        match kind {
            PsiKind::Some => some = Some(bucket),
            PsiKind::Full => full = Some(bucket),
        }
    }
    let Some(some) = some else {
        return Err(PsiError::Parse {
            resource,
            line: contents.to_string(),
            reason: "missing 'some' line".to_string(),
        });
    };
    Ok(PsiResourceReading { some, full })
}

// ============================================================================
// PsiSource trait
// ============================================================================

/// Effector-style stubbable boundary between the scheduler and the
/// PSI substrate. The scheduler calls `read()` once per sample tick
/// and routes the resulting `PsiReading` into a
/// [`crate::ResourceMeasurements`].
pub trait PsiSource: Send + Sync {
    /// Take a snapshot of all three PSI domains. Implementations
    /// SHOULD be O(constant) (3 small file reads).
    ///
    /// # Errors
    ///
    /// Returns `PsiError::Unavailable` if PSI substrate is absent
    /// (honest-offline); `PsiError::Io` on transient IO failure;
    /// `PsiError::Parse` on kernel-format drift.
    fn read(&self) -> Result<PsiReading, PsiError>;
}

// ============================================================================
// ProcfsPsiSource (real-substrate impl)
// ============================================================================

/// Real-substrate `PsiSource` reading `/proc/pressure/{cpu,memory,io}`.
/// Honest-offline: if the pressure dir or any constituent file is
/// absent, `read()` returns `PsiError::Unavailable`.
#[derive(Debug, Clone)]
pub struct ProcfsPsiSource {
    pressure_dir: PathBuf,
}

impl ProcfsPsiSource {
    /// Construct against the default `/proc/pressure/` directory.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pressure_dir: PathBuf::from(PROCFS_PRESSURE_DIR),
        }
    }

    /// Construct against a custom pressure-directory root (used by
    /// the test suite which writes fake `/proc/pressure/` trees under
    /// `tempfile::tempdir()`).
    #[must_use]
    pub fn with_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            pressure_dir: dir.into(),
        }
    }

    /// Borrow the pressure-directory path.
    #[must_use]
    pub fn pressure_dir(&self) -> &Path {
        &self.pressure_dir
    }
}

impl Default for ProcfsPsiSource {
    fn default() -> Self {
        Self::new()
    }
}

impl PsiSource for ProcfsPsiSource {
    fn read(&self) -> Result<PsiReading, PsiError> {
        if !self.pressure_dir.is_dir() {
            return Err(PsiError::Unavailable(format!(
                "{} not present (kernel < 4.20 or CONFIG_PSI=n)",
                self.pressure_dir.display()
            )));
        }
        let cpu = read_resource(&self.pressure_dir, "cpu")?;
        let memory = read_resource(&self.pressure_dir, "memory")?;
        let io = read_resource(&self.pressure_dir, "io")?;
        let captured_at_unix_micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros())
            .unwrap_or(0);
        Ok(PsiReading {
            captured_at_unix_micros,
            cpu,
            memory,
            io,
        })
    }
}

fn read_resource(
    pressure_dir: &Path,
    resource: &'static str,
) -> Result<PsiResourceReading, PsiError> {
    let path = pressure_dir.join(resource);
    if !path.is_file() {
        return Err(PsiError::Unavailable(format!(
            "{} not present",
            path.display()
        )));
    }
    let contents = fs::read_to_string(&path).map_err(|source| PsiError::Io {
        resource,
        source,
    })?;
    parse_psi_file_contents(resource, &contents)
}

// ============================================================================
// MockPsiSource (test injector)
// ============================================================================

/// In-memory `PsiSource` for tests. Returns a fixed `PsiReading`
/// constructed via `with_cpu` / `with_mem` / `with_io` (each takes
/// the `some.avg10` fraction; the other fields default to 0).
#[derive(Debug, Clone, Copy)]
pub struct MockPsiSource {
    cpu_avg10: f32,
    mem_avg10: f32,
    io_avg10: f32,
    fail_with: Option<MockFailureMode>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum MockFailureMode {
    Unavailable,
}

impl MockPsiSource {
    /// All-clean source — every domain reports 0% pressure.
    #[must_use]
    pub const fn clean() -> Self {
        Self {
            cpu_avg10: 0.0,
            mem_avg10: 0.0,
            io_avg10: 0.0,
            fail_with: None,
        }
    }

    /// Set the CPU `some.avg10` reading (0.0–1.0). Other domains
    /// untouched.
    #[must_use]
    pub const fn with_cpu(mut self, cpu_avg10: f32) -> Self {
        self.cpu_avg10 = cpu_avg10;
        self
    }

    /// Set the memory `some.avg10` reading.
    #[must_use]
    pub const fn with_mem(mut self, mem_avg10: f32) -> Self {
        self.mem_avg10 = mem_avg10;
        self
    }

    /// Set the IO `some.avg10` reading.
    #[must_use]
    pub const fn with_io(mut self, io_avg10: f32) -> Self {
        self.io_avg10 = io_avg10;
        self
    }

    /// Make `read()` return `PsiError::Unavailable` — simulates
    /// honest-offline (CONFIG_PSI=n).
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            cpu_avg10: 0.0,
            mem_avg10: 0.0,
            io_avg10: 0.0,
            fail_with: Some(MockFailureMode::Unavailable),
        }
    }
}

impl PsiSource for MockPsiSource {
    fn read(&self) -> Result<PsiReading, PsiError> {
        if let Some(MockFailureMode::Unavailable) = self.fail_with {
            return Err(PsiError::Unavailable("mock unavailable".to_string()));
        }
        let bucket = |avg10: f32| PsiBucket {
            avg10,
            avg60: 0.0,
            avg300: 0.0,
            total_micros: 0,
        };
        Ok(PsiReading {
            captured_at_unix_micros: 0,
            cpu: PsiResourceReading {
                some: bucket(self.cpu_avg10),
                full: None,
            },
            memory: PsiResourceReading {
                some: bucket(self.mem_avg10),
                full: Some(bucket(self.mem_avg10)),
            },
            io: PsiResourceReading {
                some: bucket(self.io_avg10),
                full: Some(bucket(self.io_avg10)),
            },
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

    fn write_pressure_file(dir: &Path, resource: &str, contents: &str) {
        let path = dir.join(resource);
        fs::write(&path, contents).expect("write pressure fixture");
    }

    // ---------------- parse_psi_line --------------------------------------

    #[test]
    fn parses_canonical_some_line() {
        let line = "some avg10=12.34 avg60=5.00 avg300=1.00 total=12345";
        let (kind, bucket) = parse_psi_line("cpu", line).unwrap().unwrap();
        assert_eq!(kind, PsiKind::Some);
        assert!((bucket.avg10 - 0.1234).abs() < 1e-5);
        assert!((bucket.avg60 - 0.05).abs() < 1e-5);
        assert!((bucket.avg300 - 0.01).abs() < 1e-5);
        assert_eq!(bucket.total_micros, 12345);
    }

    #[test]
    fn parses_canonical_full_line() {
        let line = "full avg10=0.00 avg60=0.00 avg300=0.00 total=0";
        let (kind, bucket) = parse_psi_line("memory", line).unwrap().unwrap();
        assert_eq!(kind, PsiKind::Full);
        assert_eq!(bucket, PsiBucket::clean());
    }

    #[test]
    fn empty_line_returns_none() {
        assert!(parse_psi_line("cpu", "").unwrap().is_none());
        assert!(parse_psi_line("cpu", "   \t  ").unwrap().is_none());
    }

    #[test]
    fn unknown_kind_rejected() {
        let err = parse_psi_line("cpu", "xxx avg10=0 avg60=0 avg300=0 total=0").unwrap_err();
        assert!(matches!(err, PsiError::Parse { .. }));
    }

    #[test]
    fn missing_total_rejected() {
        let err = parse_psi_line("cpu", "some avg10=0 avg60=0 avg300=0").unwrap_err();
        let PsiError::Parse { reason, .. } = err else {
            panic!("expected Parse")
        };
        assert!(reason.contains("missing"));
    }

    #[test]
    fn missing_avg300_rejected() {
        let err = parse_psi_line("cpu", "some avg10=0 avg60=0 total=42").unwrap_err();
        let PsiError::Parse { reason, .. } = err else {
            panic!("expected Parse")
        };
        assert!(reason.contains("missing"));
    }

    #[test]
    fn malformed_token_no_equals_rejected() {
        let err =
            parse_psi_line("cpu", "some avg10=0 noequals avg60=0 avg300=0 total=0").unwrap_err();
        assert!(matches!(err, PsiError::Parse { .. }));
    }

    #[test]
    fn non_numeric_avg_rejected() {
        let err = parse_psi_line("cpu", "some avg10=abc avg60=0 avg300=0 total=0").unwrap_err();
        assert!(matches!(err, PsiError::Parse { .. }));
    }

    #[test]
    fn out_of_range_avg_rejected() {
        let err = parse_psi_line("cpu", "some avg10=150 avg60=0 avg300=0 total=0").unwrap_err();
        let PsiError::Parse { reason, .. } = err else {
            panic!("expected Parse")
        };
        assert!(reason.contains("outside"));
    }

    #[test]
    fn extra_unknown_token_tolerated_but_canonical_still_required() {
        // Unknown tokens silently accepted (forward-compat with future
        // kernel fields); the canonical four are still required.
        let line = "some avg10=0 avg60=0 avg300=0 total=0 future=999";
        let (_, bucket) = parse_psi_line("cpu", line).unwrap().unwrap();
        assert_eq!(bucket.total_micros, 0);
    }

    #[test]
    fn tokens_in_unusual_order_accepted() {
        let line = "some total=1000 avg10=0 avg300=0 avg60=0";
        let (_, bucket) = parse_psi_line("cpu", line).unwrap().unwrap();
        assert_eq!(bucket.total_micros, 1000);
    }

    // ---------------- parse_psi_file_contents -----------------------------

    #[test]
    fn cpu_file_some_only_parses() {
        let contents = "some avg10=10.0 avg60=5.0 avg300=1.0 total=42\n";
        let reading = parse_psi_file_contents("cpu", contents).unwrap();
        assert!((reading.some.avg10 - 0.1).abs() < 1e-5);
        assert!(reading.full.is_none());
    }

    #[test]
    fn memory_file_some_and_full_parses() {
        let contents = "\
some avg10=20.0 avg60=10.0 avg300=2.0 total=999
full avg10=15.0 avg60=8.0 avg300=1.5 total=500
";
        let reading = parse_psi_file_contents("memory", contents).unwrap();
        assert!((reading.some.avg10 - 0.20).abs() < 1e-5);
        assert!((reading.full.unwrap().avg10 - 0.15).abs() < 1e-5);
    }

    #[test]
    fn file_without_some_line_rejected() {
        let contents = "full avg10=0 avg60=0 avg300=0 total=0\n";
        let err = parse_psi_file_contents("memory", contents).unwrap_err();
        let PsiError::Parse { reason, .. } = err else {
            panic!("expected Parse")
        };
        assert!(reason.contains("'some'"));
    }

    #[test]
    fn empty_file_rejected() {
        let err = parse_psi_file_contents("cpu", "").unwrap_err();
        assert!(matches!(err, PsiError::Parse { .. }));
    }

    #[test]
    fn blank_lines_in_middle_ignored() {
        let contents = "\
some avg10=0 avg60=0 avg300=0 total=0

full avg10=0 avg60=0 avg300=0 total=0

";
        let reading = parse_psi_file_contents("io", contents).unwrap();
        assert_eq!(reading.some, PsiBucket::clean());
        assert!(reading.full.is_some());
    }

    // ---------------- ProcfsPsiSource -------------------------------------

    #[test]
    fn procfs_reads_complete_triple() {
        let tmp = tempdir().unwrap();
        write_pressure_file(
            tmp.path(),
            "cpu",
            "some avg10=11.0 avg60=5.0 avg300=1.0 total=1000\n",
        );
        write_pressure_file(
            tmp.path(),
            "memory",
            "some avg10=22.0 avg60=10.0 avg300=2.0 total=2000\nfull avg10=15.0 avg60=8.0 avg300=1.5 total=500\n",
        );
        write_pressure_file(
            tmp.path(),
            "io",
            "some avg10=33.0 avg60=15.0 avg300=3.0 total=3000\nfull avg10=22.0 avg60=11.0 avg300=2.2 total=1500\n",
        );
        let src = ProcfsPsiSource::with_dir(tmp.path());
        let reading = src.read().unwrap();
        assert!((reading.cpu_some_avg10() - 0.11).abs() < 1e-5);
        assert!((reading.mem_some_avg10() - 0.22).abs() < 1e-5);
        assert!((reading.io_some_avg10() - 0.33).abs() < 1e-5);
        assert!(reading.cpu.full.is_none());
        assert!(reading.memory.full.is_some());
        assert!(reading.io.full.is_some());
    }

    #[test]
    fn procfs_honest_offline_dir_missing() {
        let tmp = tempdir().unwrap();
        let nonexistent = tmp.path().join("never-created");
        let src = ProcfsPsiSource::with_dir(&nonexistent);
        let err = src.read().unwrap_err();
        assert!(matches!(err, PsiError::Unavailable(_)));
    }

    #[test]
    fn procfs_honest_offline_one_resource_missing() {
        // Cpu + memory present, io missing → Unavailable on io.
        let tmp = tempdir().unwrap();
        write_pressure_file(
            tmp.path(),
            "cpu",
            "some avg10=0 avg60=0 avg300=0 total=0\n",
        );
        write_pressure_file(
            tmp.path(),
            "memory",
            "some avg10=0 avg60=0 avg300=0 total=0\nfull avg10=0 avg60=0 avg300=0 total=0\n",
        );
        let src = ProcfsPsiSource::with_dir(tmp.path());
        let err = src.read().unwrap_err();
        assert!(matches!(err, PsiError::Unavailable(_)));
    }

    #[test]
    fn procfs_parse_error_propagates() {
        let tmp = tempdir().unwrap();
        write_pressure_file(tmp.path(), "cpu", "garbage\n");
        write_pressure_file(
            tmp.path(),
            "memory",
            "some avg10=0 avg60=0 avg300=0 total=0\nfull avg10=0 avg60=0 avg300=0 total=0\n",
        );
        write_pressure_file(
            tmp.path(),
            "io",
            "some avg10=0 avg60=0 avg300=0 total=0\nfull avg10=0 avg60=0 avg300=0 total=0\n",
        );
        let src = ProcfsPsiSource::with_dir(tmp.path());
        let err = src.read().unwrap_err();
        assert!(matches!(err, PsiError::Parse { resource: "cpu", .. }));
    }

    #[test]
    fn procfs_captured_at_advances() {
        let tmp = tempdir().unwrap();
        write_pressure_file(
            tmp.path(),
            "cpu",
            "some avg10=0 avg60=0 avg300=0 total=0\n",
        );
        write_pressure_file(
            tmp.path(),
            "memory",
            "some avg10=0 avg60=0 avg300=0 total=0\nfull avg10=0 avg60=0 avg300=0 total=0\n",
        );
        write_pressure_file(
            tmp.path(),
            "io",
            "some avg10=0 avg60=0 avg300=0 total=0\nfull avg10=0 avg60=0 avg300=0 total=0\n",
        );
        let src = ProcfsPsiSource::with_dir(tmp.path());
        let r1 = src.read().unwrap();
        let r2 = src.read().unwrap();
        // captured_at advances monotonically across reads (or is equal
        // on coarse clocks). It is NOT allowed to go backward.
        assert!(r2.captured_at_unix_micros >= r1.captured_at_unix_micros);
    }

    // ---------------- MockPsiSource ---------------------------------------

    #[test]
    fn mock_clean_returns_zeros() {
        let src = MockPsiSource::clean();
        let reading = src.read().unwrap();
        assert_eq!(reading.cpu_some_avg10(), 0.0);
        assert_eq!(reading.mem_some_avg10(), 0.0);
        assert_eq!(reading.io_some_avg10(), 0.0);
    }

    #[test]
    fn mock_with_setters_chain() {
        let src = MockPsiSource::clean()
            .with_cpu(0.5)
            .with_mem(0.25)
            .with_io(0.1);
        let reading = src.read().unwrap();
        assert_eq!(reading.cpu_some_avg10(), 0.5);
        assert_eq!(reading.mem_some_avg10(), 0.25);
        assert_eq!(reading.io_some_avg10(), 0.1);
    }

    #[test]
    fn mock_unavailable_returns_unavailable() {
        let src = MockPsiSource::unavailable();
        let err = src.read().unwrap_err();
        assert!(matches!(err, PsiError::Unavailable(_)));
    }

    // ---------------- PsiSource trait object ------------------------------

    #[test]
    fn trait_object_dispatch_works() {
        // Confirms PsiSource is dyn-compatible — needed for the
        // scheduler to hold a boxed PsiSource for runtime selection
        // between ProcfsPsiSource (production) and MockPsiSource (tests).
        let sources: Vec<Box<dyn PsiSource>> = vec![
            Box::new(MockPsiSource::clean().with_cpu(0.1)),
            Box::new(MockPsiSource::clean().with_mem(0.2)),
        ];
        let readings: Vec<f32> = sources
            .iter()
            .map(|s| {
                let r = s.read().unwrap();
                r.cpu_some_avg10() + r.mem_some_avg10()
            })
            .collect();
        assert_eq!(readings, vec![0.1, 0.2]);
    }

    // ---------------- Constants -------------------------------------------

    #[test]
    fn procfs_pressure_dir_constant_matches_kernel_doc() {
        assert_eq!(PROCFS_PRESSURE_DIR, "/proc/pressure");
        assert_eq!(KIND_SOME, "some");
        assert_eq!(KIND_FULL, "full");
    }
}
