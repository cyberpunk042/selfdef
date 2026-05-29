//! `selfdef-scheduler::prometheus_exporter` — M01168: Prometheus
//! exposition-format renderer for `BackpressureDriver` output.
//!
//! Dump grounding (avx-plus-plus 2026-05-18 line 18197):
//! > *"Linux PSI + DCGM + trace metrics feed the scheduler"*
//!
//! Catalog grounding: MS048 module `M01168 selfdef-scheduler-prometheus-
//! exporter` per `~/selfdef/backlog/milestones/MS048-goldilocks-
//! scheduler-hardware-aware-resource-routing.md`.
//!
//! Doctrinal anchor: [Peace Machine + Core Law](https://github.com/
//! cyberpunk042/devops-solutions-information-hub/blob/main/wiki/spine/
//! doctrine/peace-machine-and-core-law.md) — peace-machine clause
//! "disciplined enough to explain itself" (every scheduler decision +
//! every substrate state is observable as a Prometheus gauge the
//! cockpit can render alongside the 14 IPS axes already on
//! IPS-host-overview).
//!
//! ## What this module provides
//!
//! 1. `render_prometheus(&DriverReading) -> String` — produces
//!    text-format gauges for every field of `ResourceMeasurements`,
//!    every field of `BackpressureState`, every per-source health
//!    state, plus `selfdef_scheduler_last_run_unix` for observer
//!    freshness and `selfdef_scheduler_textfile_emit_failed` as the
//!    sentinel used by the existing 14-sibling observer pattern.
//! 2. `write_textfile_atomic(path, contents)` — atomic `mktemp` +
//!    `rename(2)` write convention matching the IPS observers
//!    (`packaging/scripts/selfdef-*-textfile.sh` siblings).
//!    Sentinel-emit on failure is the caller's responsibility (the
//!    rendered string includes the success sentinel; an external
//!    error trap writes the failure sentinel instead).
//! 3. `DEFAULT_TEXTFILE_PATH` — the canonical
//!    `/var/lib/node_exporter/textfile_collector/selfdef-scheduler.prom`
//!    location, parallel to the 14 IPS observer outputs.
//!
//! ## Why one renderer, not an HTTP server
//!
//! The 14 IPS observers all use the node_exporter textfile collector
//! pattern: each observer writes `*.prom` to a known directory,
//! node_exporter serves them. That keeps the scheduler off the
//! network (PrivateNetwork=true preserved in the systemd hardening)
//! and consistent with the IPS observer architecture. An embedded
//! HTTP server would violate the network-boundary discipline.
//!
//! ## Gauge naming
//!
//! All gauges prefixed `selfdef_scheduler_*` to namespace cleanly
//! from the `selfdef_<primitive>_*` gauges emitted by the 14 IPS
//! observers. The full set:
//!
//! ```text
//! Measurements:
//!   selfdef_scheduler_cpu_psi              (gauge, 0.0-1.0)
//!   selfdef_scheduler_mem_psi              (gauge, 0.0-1.0)
//!   selfdef_scheduler_io_psi               (gauge, 0.0-1.0)
//!   selfdef_scheduler_blackwell_vram_util  (gauge, 0.0-1.0)
//!   selfdef_scheduler_gpu3090_util         (gauge, 0.0-1.0)
//!   selfdef_scheduler_human_gate_queue_depth (gauge, count)
//!
//! Backpressure state (0/1):
//!   selfdef_scheduler_cpu_pressure
//!   selfdef_scheduler_ram_pressure
//!   selfdef_scheduler_io_pressure
//!   selfdef_scheduler_blackwell_vram_high
//!   selfdef_scheduler_gpu3090_busy
//!   selfdef_scheduler_human_gate_queue_high
//!
//! Substrate health (labeled gauge, value 0/1 — healthy is 1):
//!   selfdef_scheduler_substrate_healthy{source="psi"}
//!   selfdef_scheduler_substrate_healthy{source="dcgm"}
//!   selfdef_scheduler_substrate_healthy{source="human_gate"}
//!
//! Substrate degraded count (rollup):
//!   selfdef_scheduler_substrate_degraded_count (gauge, 0..=3)
//!
//! Observer freshness + sentinel:
//!   selfdef_scheduler_last_run_unix         (gauge, seconds)
//!   selfdef_scheduler_textfile_emit_failed  (gauge, 0/1)
//! ```
//!
//! ## Non-goals
//!
//! - Not a polling driver. This module renders one snapshot; the
//!   caller (systemd timer / scheduler observe loop) decides cadence.
//! - Not an OCSF emitter (separate module M01169).
//! - Not a histogram aggregator. Gauges only.
//!
//! Standing rule: We do not minimize anything.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::backpressure_driver::{DriverReading, SourceStatus};

/// Canonical textfile collector path. Matches the convention used
/// by the 14 IPS observers (`packaging/scripts/selfdef-*-textfile.sh`).
pub const DEFAULT_TEXTFILE_PATH: &str =
    "/var/lib/node_exporter/textfile_collector/selfdef-scheduler.prom";

/// Render a `DriverReading` into Prometheus text-format. Output is
/// deterministic: all gauges emitted in a fixed order, regardless
/// of the underlying `SubstrateHealth` variants.
#[must_use]
pub fn render_prometheus(reading: &DriverReading) -> String {
    let mut out = String::with_capacity(4096);
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // --- Measurements (continuous) ---
    emit_gauge(
        &mut out,
        "selfdef_scheduler_cpu_psi",
        "CPU PSI some/avg10 fraction (0.0-1.0) sourced from /proc/pressure/cpu.",
        reading.measurements.cpu_psi as f64,
    );
    emit_gauge(
        &mut out,
        "selfdef_scheduler_mem_psi",
        "Memory PSI some/avg10 fraction (0.0-1.0) sourced from /proc/pressure/memory.",
        reading.measurements.mem_psi as f64,
    );
    emit_gauge(
        &mut out,
        "selfdef_scheduler_io_psi",
        "IO PSI some/avg10 fraction (0.0-1.0) sourced from /proc/pressure/io.",
        reading.measurements.io_psi as f64,
    );
    emit_gauge(
        &mut out,
        "selfdef_scheduler_blackwell_vram_util",
        "RTX PRO 6000 Blackwell VRAM utilization fraction (0.0-1.0) sourced from nvidia-smi.",
        reading.measurements.blackwell_vram_util as f64,
    );
    emit_gauge(
        &mut out,
        "selfdef_scheduler_gpu3090_util",
        "RTX 3090 compute utilization fraction (0.0-1.0) sourced from nvidia-smi.",
        reading.measurements.gpu3090_util as f64,
    );
    emit_gauge(
        &mut out,
        "selfdef_scheduler_human_gate_queue_depth",
        "Sum of pending operator-decision queue entries across 14 IPS primitives.",
        f64::from(reading.measurements.human_gate_queue_depth),
    );

    // --- Backpressure state (booleans as 0/1) ---
    emit_gauge_bool(
        &mut out,
        "selfdef_scheduler_cpu_pressure",
        "1 if CPU PSI threshold crossed (R11340 + hysteresis).",
        reading.state.cpu_pressure,
    );
    emit_gauge_bool(
        &mut out,
        "selfdef_scheduler_ram_pressure",
        "1 if memory PSI threshold crossed (R11343 + hysteresis).",
        reading.state.ram_pressure,
    );
    emit_gauge_bool(
        &mut out,
        "selfdef_scheduler_io_pressure",
        "1 if IO PSI threshold crossed (R11346 + hysteresis).",
        reading.state.io_pressure,
    );
    emit_gauge_bool(
        &mut out,
        "selfdef_scheduler_blackwell_vram_high",
        "1 if Blackwell VRAM threshold crossed (R11333 + hysteresis).",
        reading.state.blackwell_vram_high,
    );
    emit_gauge_bool(
        &mut out,
        "selfdef_scheduler_gpu3090_busy",
        "1 if 3090 utilization threshold crossed (R11337 + hysteresis).",
        reading.state.gpu3090_busy,
    );
    emit_gauge_bool(
        &mut out,
        "selfdef_scheduler_human_gate_queue_high",
        "1 if pending operator-decision count > R11349 threshold.",
        reading.state.human_gate_queue_high,
    );

    // --- Substrate health (labeled gauge — 1 = healthy, 0 = degraded) ---
    out.push_str("# HELP selfdef_scheduler_substrate_healthy 1 if substrate source is Healthy, 0 if Unavailable (honest-offline) or Errored.\n");
    out.push_str("# TYPE selfdef_scheduler_substrate_healthy gauge\n");
    emit_substrate_healthy(&mut out, "psi", &reading.substrate_health.psi_status);
    emit_substrate_healthy(&mut out, "dcgm", &reading.substrate_health.dcgm_status);
    emit_substrate_healthy(
        &mut out,
        "human_gate",
        &reading.substrate_health.human_gate_status,
    );

    // Status detail label (only emitted when degraded) so the cockpit
    // can render the Unavailable/Errored reason without scraping logs.
    out.push_str("# HELP selfdef_scheduler_substrate_status Reason text for degraded substrate sources (label-encoded; value always 1).\n");
    out.push_str("# TYPE selfdef_scheduler_substrate_status gauge\n");
    emit_substrate_status(&mut out, "psi", &reading.substrate_health.psi_status);
    emit_substrate_status(&mut out, "dcgm", &reading.substrate_health.dcgm_status);
    emit_substrate_status(
        &mut out,
        "human_gate",
        &reading.substrate_health.human_gate_status,
    );

    emit_gauge(
        &mut out,
        "selfdef_scheduler_substrate_degraded_count",
        "Count of substrate sources reporting Unavailable or Errored (0..=3).",
        f64::from(reading.substrate_health.degraded_count()),
    );

    // --- Observer freshness ---
    emit_gauge(
        &mut out,
        "selfdef_scheduler_last_run_unix",
        "Wall-clock unix seconds of last scheduler poll (observer freshness).",
        now_unix as f64,
    );

    // --- Success sentinel (parallel to IPS observers'
    //     selfdef_<primitive>_textfile_emit_failed) ---
    emit_gauge(
        &mut out,
        "selfdef_scheduler_textfile_emit_failed",
        "Wrapper exited unhealthy (0 on success). Parallel to IPS observers' sentinel.",
        0.0,
    );

    out
}

fn emit_gauge(out: &mut String, name: &str, help: &str, value: f64) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} gauge");
    let _ = writeln!(out, "{name} {value}");
}

fn emit_gauge_bool(out: &mut String, name: &str, help: &str, value: bool) {
    emit_gauge(out, name, help, if value { 1.0 } else { 0.0 });
}

fn emit_substrate_healthy(out: &mut String, source: &str, status: &SourceStatus) {
    let value = if status.is_healthy() { 1.0 } else { 0.0 };
    let _ = writeln!(out, "selfdef_scheduler_substrate_healthy{{source=\"{source}\"}} {value}");
}

fn emit_substrate_status(out: &mut String, source: &str, status: &SourceStatus) {
    let (kind, reason) = match status {
        SourceStatus::Healthy => return,
        SourceStatus::Unavailable(r) => ("unavailable", r.as_str()),
        SourceStatus::Errored(r) => ("errored", r.as_str()),
    };
    let escaped = escape_label_value(reason);
    let _ = writeln!(
        out,
        "selfdef_scheduler_substrate_status{{source=\"{source}\",kind=\"{kind}\",reason=\"{escaped}\"}} 1"
    );
}

/// Escape a Prometheus label value per the exposition spec:
/// backslash → `\\`, newline → `\n`, double-quote → `\"`.
fn escape_label_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str(r"\\"),
            '\n' => out.push_str(r"\n"),
            '"' => out.push_str(r#"\""#),
            c => out.push(c),
        }
    }
    out
}

/// Write `contents` to `target` atomically via `mktemp` + `rename(2)`
/// — same pattern the 14 IPS observer scripts use.
///
/// # Errors
///
/// Returns an `std::io::Error` if `mktemp`-style write or rename fails.
pub fn write_textfile_atomic(target: &Path, contents: &str) -> std::io::Result<()> {
    let parent = target.parent().ok_or_else(|| {
        std::io::Error::other(format!("target {} has no parent", target.display()))
    })?;
    fs::create_dir_all(parent).ok();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let file_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("selfdef-scheduler.prom");
    let tmp: PathBuf = parent.join(format!("{file_name}.tmp.{pid}.{nanos}"));
    fs::write(&tmp, contents)?;
    // Permission bits 0644 to match the IPS observers (operator group
    // reads, node_exporter scrapes).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&tmp)?.permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&tmp, perms)?;
    }
    if let Err(e) = fs::rename(&tmp, target) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Render the failure sentinel that an ERR-trap in the driver loop
/// writes when `poll()` itself panics (rather than returning a clean
/// DriverReading). Parallels the IPS observer `emit_failure_sentinel`
/// shell functions.
#[must_use]
pub fn render_failure_sentinel() -> String {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut out = String::with_capacity(512);
    emit_gauge(
        &mut out,
        "selfdef_scheduler_textfile_emit_failed",
        "Scheduler driver exited unhealthy (1 on failure).",
        1.0,
    );
    emit_gauge(
        &mut out,
        "selfdef_scheduler_last_run_unix",
        "Wall-clock unix seconds of last (failed) scheduler poll.",
        now_unix as f64,
    );
    out
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

    fn sample_reading() -> DriverReading {
        DriverReading {
            captured_at_unix_micros: 1_700_000_000_000_000,
            measurements: ResourceMeasurements {
                blackwell_vram_util: 0.85,
                gpu3090_util: 0.40,
                cpu_psi: 0.20,
                mem_psi: 0.10,
                io_psi: 0.05,
                human_gate_queue_depth: 3,
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

    // ---------------- render_prometheus content -------------------------

    #[test]
    fn renders_all_measurement_gauges_with_values() {
        let r = sample_reading();
        let out = render_prometheus(&r);
        assert!(out.contains("selfdef_scheduler_cpu_psi 0.2"));
        assert!(out.contains("selfdef_scheduler_mem_psi 0.1"));
        assert!(out.contains("selfdef_scheduler_io_psi 0.05"));
        assert!(out.contains("selfdef_scheduler_blackwell_vram_util 0.85"));
        assert!(out.contains("selfdef_scheduler_gpu3090_util 0.4"));
        assert!(out.contains("selfdef_scheduler_human_gate_queue_depth 3"));
    }

    #[test]
    fn renders_all_backpressure_state_booleans() {
        let mut r = sample_reading();
        r.state.cpu_pressure = true;
        r.state.blackwell_vram_high = true;
        r.state.human_gate_queue_high = true;
        let out = render_prometheus(&r);
        assert!(out.contains("selfdef_scheduler_cpu_pressure 1"));
        assert!(out.contains("selfdef_scheduler_blackwell_vram_high 1"));
        assert!(out.contains("selfdef_scheduler_human_gate_queue_high 1"));
        assert!(out.contains("selfdef_scheduler_ram_pressure 0"));
        assert!(out.contains("selfdef_scheduler_io_pressure 0"));
        assert!(out.contains("selfdef_scheduler_gpu3090_busy 0"));
    }

    #[test]
    fn renders_substrate_healthy_labels_for_three_sources() {
        let out = render_prometheus(&sample_reading());
        assert!(out.contains("selfdef_scheduler_substrate_healthy{source=\"psi\"} 1"));
        assert!(out.contains("selfdef_scheduler_substrate_healthy{source=\"dcgm\"} 1"));
        assert!(out.contains("selfdef_scheduler_substrate_healthy{source=\"human_gate\"} 1"));
        assert!(out.contains("selfdef_scheduler_substrate_degraded_count 0"));
    }

    #[test]
    fn renders_substrate_unavailable_with_reason_label() {
        let mut r = sample_reading();
        r.substrate_health.psi_status =
            SourceStatus::Unavailable("kernel < 4.20".to_string());
        let out = render_prometheus(&r);
        assert!(out.contains("selfdef_scheduler_substrate_healthy{source=\"psi\"} 0"));
        assert!(out.contains(
            "selfdef_scheduler_substrate_status{source=\"psi\",kind=\"unavailable\",reason=\"kernel < 4.20\"} 1"
        ));
        assert!(out.contains("selfdef_scheduler_substrate_degraded_count 1"));
    }

    #[test]
    fn renders_substrate_errored_with_reason_label() {
        let mut r = sample_reading();
        r.substrate_health.dcgm_status = SourceStatus::Errored("driver crash".to_string());
        let out = render_prometheus(&r);
        assert!(out.contains("selfdef_scheduler_substrate_healthy{source=\"dcgm\"} 0"));
        assert!(out.contains(
            "selfdef_scheduler_substrate_status{source=\"dcgm\",kind=\"errored\",reason=\"driver crash\"} 1"
        ));
    }

    #[test]
    fn renders_all_three_degraded_count_three() {
        let mut r = sample_reading();
        r.substrate_health.psi_status = SourceStatus::Unavailable("a".into());
        r.substrate_health.dcgm_status = SourceStatus::Errored("b".into());
        r.substrate_health.human_gate_status = SourceStatus::Unavailable("c".into());
        let out = render_prometheus(&r);
        assert!(out.contains("selfdef_scheduler_substrate_degraded_count 3"));
    }

    #[test]
    fn healthy_substrate_does_not_emit_status_row() {
        let out = render_prometheus(&sample_reading());
        // Ensure no spurious substrate_status row appears for healthy sources.
        // We allow the HELP/TYPE headers (they're informational) but no data row.
        for source in &["psi", "dcgm", "human_gate"] {
            let needle = format!("selfdef_scheduler_substrate_status{{source=\"{source}\"");
            assert!(
                !out.contains(&needle),
                "healthy {source} should not emit substrate_status row"
            );
        }
    }

    #[test]
    fn renders_observer_freshness_and_success_sentinel() {
        let out = render_prometheus(&sample_reading());
        assert!(out.contains("selfdef_scheduler_last_run_unix"));
        assert!(out.contains("selfdef_scheduler_textfile_emit_failed 0"));
    }

    #[test]
    fn renders_help_and_type_for_every_gauge() {
        let out = render_prometheus(&sample_reading());
        let help_lines = out.matches("# HELP ").count();
        let type_lines = out.matches("# TYPE ").count();
        // Each gauge name appears once in HELP + once in TYPE.
        assert_eq!(
            help_lines, type_lines,
            "HELP and TYPE counts must match (got HELP={help_lines}, TYPE={type_lines})"
        );
        assert!(help_lines >= 16, "expected ≥16 HELP rows, got {help_lines}");
    }

    // ---------------- Label-value escaping --------------------------------

    #[test]
    fn escapes_backslash_newline_quote_in_reason() {
        let raw = r#"path "/var\name" has newline
inside"#;
        let mut r = sample_reading();
        r.substrate_health.psi_status = SourceStatus::Errored(raw.to_string());
        let out = render_prometheus(&r);
        // Expect the raw special chars to NOT appear as-is in the
        // label value position.
        // The escaped form contains \\ \" \n.
        let expected = r#"selfdef_scheduler_substrate_status{source="psi",kind="errored",reason="path \"/var\\name\" has newline\ninside"} 1"#;
        assert!(
            out.contains(expected),
            "expected escaped row in output; got\n{out}"
        );
    }

    // ---------------- write_textfile_atomic -------------------------------

    #[test]
    fn write_textfile_atomic_creates_target_with_contents() {
        let tmp = tempdir().unwrap();
        let target = tmp.path().join("selfdef-scheduler.prom");
        let payload = render_prometheus(&sample_reading());
        write_textfile_atomic(&target, &payload).unwrap();
        let read_back = fs::read_to_string(&target).unwrap();
        assert_eq!(read_back, payload);
    }

    #[test]
    fn write_textfile_atomic_leaves_no_tmpfile() {
        let tmp = tempdir().unwrap();
        let target = tmp.path().join("selfdef-scheduler.prom");
        write_textfile_atomic(&target, "x").unwrap();
        let entries: Vec<String> = fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec!["selfdef-scheduler.prom"]);
    }

    #[test]
    fn write_textfile_atomic_replaces_existing_target() {
        let tmp = tempdir().unwrap();
        let target = tmp.path().join("selfdef-scheduler.prom");
        fs::write(&target, "old contents").unwrap();
        write_textfile_atomic(&target, "new contents").unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "new contents");
    }

    #[cfg(unix)]
    #[test]
    fn write_textfile_atomic_sets_permissions_0644() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempdir().unwrap();
        let target = tmp.path().join("selfdef-scheduler.prom");
        write_textfile_atomic(&target, "x").unwrap();
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "expected 0644, got {mode:o}");
    }

    #[test]
    fn write_textfile_atomic_creates_parent_dir() {
        let tmp = tempdir().unwrap();
        let target = tmp.path().join("nested").join("dir").join("scheduler.prom");
        write_textfile_atomic(&target, "x").unwrap();
        assert!(target.exists());
    }

    // ---------------- render_failure_sentinel -----------------------------

    #[test]
    fn failure_sentinel_emits_one_and_freshness() {
        let out = render_failure_sentinel();
        assert!(out.contains("selfdef_scheduler_textfile_emit_failed 1"));
        assert!(out.contains("selfdef_scheduler_last_run_unix"));
    }

    // ---------------- Constants -------------------------------------------

    #[test]
    fn default_textfile_path_matches_ips_observer_convention() {
        assert_eq!(
            DEFAULT_TEXTFILE_PATH,
            "/var/lib/node_exporter/textfile_collector/selfdef-scheduler.prom"
        );
    }

    // ---------------- Determinism -----------------------------------------

    #[test]
    fn render_is_deterministic_across_two_calls_with_same_input() {
        // Excluding last_run_unix (which uses wall clock), the rest of
        // the output should be byte-identical across two renders of the
        // same DriverReading. Strip the dynamic line and compare.
        let r = sample_reading();
        let a = strip_dynamic(&render_prometheus(&r));
        let b = strip_dynamic(&render_prometheus(&r));
        assert_eq!(a, b);
    }

    fn strip_dynamic(s: &str) -> String {
        s.lines()
            .filter(|l| !l.starts_with("selfdef_scheduler_last_run_unix "))
            .collect::<Vec<_>>()
            .join("\n")
    }
}
