//! `selfdef-scheduler::tui_panel` — M01163: Terminal-UX status panel.
//!
//! Catalog grounding: MS048 module `M01163 selfdef-scheduler-tui-
//! panel` per `~/selfdef/backlog/milestones/MS048-goldilocks-
//! scheduler-hardware-aware-resource-routing.md`. Renders the
//! same data the Grafana dashboard (sovereign-os) shows, but
//! locally + offline-capable in the operator's terminal.
//!
//! Doctrinal anchor: [Peace Machine + Core Law](https://github.com/
//! cyberpunk042/devops-solutions-information-hub/blob/main/wiki/spine/
//! doctrine/peace-machine-and-core-law.md) — peace-machine clause
//! "disciplined enough to explain itself". The cockpit operator
//! who logged in via SSH and has no Grafana access (network
//! partition, fresh-bootstrap host, AIR-GAPPED workstation) can
//! still see the substrate trio + backpressure + per-source health
//! at a glance.
//!
//! ## Why not the 4-panel canonical TUI
//!
//! The MS043 TUI mirror exposes 4 canonical panels (Rules / Grants
//! / Quarantine / Authority) per R10141. Adding panels is forbidden
//! per the operator's "A dashboard should not show vanity graphs"
//! doctrine (R10298). MS048 scheduler observability is a DIFFERENT
//! axis (runtime routing layer, not IPS enforcement layer), so it
//! gets its own standalone view rather than being shoehorned into
//! the IPS 4-panel layout.
//!
//! Per the operator's project-boundary rule: scheduler observability
//! IS in selfdef (this module); its rendering is a peer of the IPS
//! TUI, not part of it.
//!
//! ## What this module provides
//!
//! 1. `render_panel(&DriverReading) -> String` — pure text view
//!    of one `DriverReading`. ASCII-only (no Unicode dep). Designed
//!    for 80-column terminals.
//! 2. `render_panel_compact(&DriverReading) -> String` — single-line
//!    summary for `tail -f`-style watching.
//! 3. `render_panel_from_textfile(textfile_path)` — convenience:
//!    re-parses the live Prometheus textfile and renders the same
//!    panel without needing a `DriverReading` in scope.
//! 4. `render_panel_from_audit_tail(audit_path)` — renders the
//!    LATEST entry of the M01170 audit log (operator-facing
//!    "what was the last state?" view).
//! 5. `PanelStyle` — operator preference for how to render
//!    (no_color / ansi_color / plain). Honors `NO_COLOR=1`
//!    convention.
//!
//! ## Non-goals
//!
//! - Not a full-screen TUI. Operators get a single rendered string
//!   they can `cat`, `less`, `tail`, pipe. Future ratatui-based
//!   full-screen TUI would be a separate slot.
//! - Not a long-running watch loop. Caller decides poll cadence
//!   (e.g. `watch -n 5 selfdefctl scheduler status`).
//! - Not a config editor. Read-only view.
//!
//! Standing rule: We do not minimize anything.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::backpressure_driver::{DriverReading, SourceStatus, SubstrateHealth};
use crate::decision_audit::DriverAuditEntry;
use crate::{BackpressureState, ResourceMeasurements};

// ============================================================================
// PanelStyle
// ============================================================================

/// Render-style preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PanelStyle {
    /// ASCII-only, no escapes. Default for non-interactive contexts.
    #[default]
    Plain,
    /// ANSI color escapes. Use when `stdout.is_terminal()` AND
    /// `NO_COLOR` env var is unset.
    AnsiColor,
}

impl PanelStyle {
    /// Decide style based on `NO_COLOR` environment convention +
    /// caller-provided `is_terminal`. Reads `NO_COLOR` from the
    /// process environment; use [`Self::decide`] for pure-function
    /// version (testable without env mutation).
    #[must_use]
    pub fn detect(is_terminal: bool) -> Self {
        Self::decide(is_terminal, env::var_os("NO_COLOR").is_some())
    }

    /// Pure decision function — caller supplies both inputs.
    /// Use this in tests + libraries that need deterministic
    /// behavior independent of the process env.
    #[must_use]
    pub const fn decide(is_terminal: bool, no_color_set: bool) -> Self {
        if no_color_set {
            Self::Plain
        } else if is_terminal {
            Self::AnsiColor
        } else {
            Self::Plain
        }
    }
}

// ============================================================================
// Render errors
// ============================================================================

/// Errors raised by file-source render entrypoints.
#[derive(Debug, Error)]
pub enum PanelError {
    /// File missing or unreadable.
    #[error("panel io ({path}): {source}")]
    Io {
        /// Path that failed.
        path: std::path::PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// Source file present but couldn't be parsed.
    #[error("panel parse ({path}): {reason}")]
    Parse {
        /// Path that failed.
        path: std::path::PathBuf,
        /// Reason.
        reason: String,
    },
}

// ============================================================================
// render_panel
// ============================================================================

/// Render one `DriverReading` as a full multi-line text panel.
///
/// Layout (80 columns):
///
/// ```text
///  MS048 Goldilocks Scheduler — at ts=... (substrate-trio + backpressure)
///  ────────────────────────────────────────────────────────────────────────
///  SUBSTRATE       Healthy   Status detail
///  PSI             [OK]      —
///  DCGM            [degr]    Unavailable: kernel driver not loaded
///  human-gate      [OK]      —
///  ────────────────────────────────────────────────────────────────────────
///  MEASUREMENTS                          THRESHOLD    STATE
///  CPU PSI               12.5%           50.0%        [OK]
///  Memory PSI            22.0%           30.0%        [OK]
///  IO PSI                 5.0%           40.0%        [OK]
///  Blackwell VRAM        89.5%           90.0%        [OK]  (in band, hys)
///  3090 utilization      28.0%           80.0%        [OK]
///  human-gate queue         3            >5           [OK]
///  ────────────────────────────────────────────────────────────────────────
///  Degraded substrates: 1/3
///  Backpressure surfaces firing: 0/6
/// ```
#[must_use]
pub fn render_panel(reading: &DriverReading) -> String {
    render_panel_styled(reading, PanelStyle::Plain)
}

/// Render with the given style.
#[must_use]
pub fn render_panel_styled(reading: &DriverReading, style: PanelStyle) -> String {
    let mut out = String::with_capacity(2048);
    let rule = "─".repeat(72);
    let r = reading;
    let m = &r.measurements;
    let s = &r.state;
    let h = &r.substrate_health;
    // The threshold defaults are the sain-01 baseline (matches
    // BackpressureThresholds::default_for_sain01). The actual
    // running thresholds may differ if the operator has tuned
    // /etc/selfdef/scheduler.toml — see the renderer's note at
    // the bottom.
    let thresholds = crate::BackpressureThresholds::default_for_sain01();

    let _ = writeln!(
        out,
        " MS048 Goldilocks Scheduler — at ts={}us (substrate-trio + backpressure)",
        r.captured_at_unix_micros
    );
    let _ = writeln!(out, " {rule}");
    let _ = writeln!(out, " SUBSTRATE         Healthy   Status detail");
    render_source_row(&mut out, "PSI", &h.psi_status, style);
    render_source_row(&mut out, "DCGM", &h.dcgm_status, style);
    render_source_row(&mut out, "human-gate", &h.human_gate_status, style);
    let _ = writeln!(out, " {rule}");
    let _ = writeln!(
        out,
        " MEASUREMENT                       THRESHOLD     STATE"
    );
    render_pct_row(
        &mut out,
        "CPU PSI",
        m.cpu_psi,
        thresholds.cpu_pressure,
        s.cpu_pressure,
        style,
    );
    render_pct_row(
        &mut out,
        "Memory PSI",
        m.mem_psi,
        thresholds.ram_pressure,
        s.ram_pressure,
        style,
    );
    render_pct_row(
        &mut out,
        "IO PSI",
        m.io_psi,
        thresholds.io_pressure,
        s.io_pressure,
        style,
    );
    render_pct_row(
        &mut out,
        "Blackwell VRAM",
        m.blackwell_vram_util,
        thresholds.blackwell_vram_high,
        s.blackwell_vram_high,
        style,
    );
    render_pct_row(
        &mut out,
        "3090 utilization",
        m.gpu3090_util,
        thresholds.gpu3090_busy,
        s.gpu3090_busy,
        style,
    );
    render_count_row(
        &mut out,
        "human-gate queue",
        m.human_gate_queue_depth,
        thresholds.human_gate_queue_high,
        s.human_gate_queue_high,
        style,
    );
    let _ = writeln!(out, " {rule}");
    let _ = writeln!(out, " Degraded substrates: {}/3", h.degraded_count());
    let _ = writeln!(
        out,
        " Backpressure surfaces firing: {}/6",
        backpressure_count(s)
    );
    let _ = writeln!(out, " {rule}");
    let _ = writeln!(
        out,
        " Note: thresholds shown are sain-01 defaults; runtime values"
    );
    let _ = writeln!(
        out,
        "       may differ if /etc/selfdef/scheduler.toml [thresholds] is set."
    );
    out
}

fn render_source_row(out: &mut String, name: &str, status: &SourceStatus, style: PanelStyle) {
    let (badge, detail) = match status {
        SourceStatus::Healthy => (colorize("[OK]  ", Color::Green, style), "—".to_string()),
        SourceStatus::Unavailable(r) => (
            colorize("[degr]", Color::Yellow, style),
            format!("Unavailable: {r}"),
        ),
        SourceStatus::Errored(r) => (
            colorize("[FAIL]", Color::Red, style),
            format!("Errored: {r}"),
        ),
    };
    let trimmed_detail = if detail.len() > 50 {
        format!("{}…", &detail[..49])
    } else {
        detail
    };
    let _ = writeln!(out, " {name:<17} {badge}    {trimmed_detail}");
}

fn render_pct_row(
    out: &mut String,
    name: &str,
    value: f32,
    threshold: f32,
    state: bool,
    style: PanelStyle,
) {
    let badge = state_badge(state, style);
    let _ = writeln!(
        out,
        " {name:<32} {:>6.1}%   {:>5.1}%        {badge}",
        value * 100.0,
        threshold * 100.0
    );
}

fn render_count_row(
    out: &mut String,
    name: &str,
    value: u32,
    threshold: u32,
    state: bool,
    style: PanelStyle,
) {
    let badge = state_badge(state, style);
    let _ = writeln!(
        out,
        " {name:<32} {value:>6}    >{threshold:<4}        {badge}"
    );
}

fn state_badge(state: bool, style: PanelStyle) -> String {
    if state {
        colorize("[fire]", Color::Red, style)
    } else {
        colorize("[OK]  ", Color::Green, style)
    }
}

#[derive(Debug, Clone, Copy)]
enum Color {
    Green,
    Yellow,
    Red,
}

fn colorize(text: &str, color: Color, style: PanelStyle) -> String {
    if !matches!(style, PanelStyle::AnsiColor) {
        return text.to_string();
    }
    let code = match color {
        Color::Green => "32",
        Color::Yellow => "33",
        Color::Red => "31",
    };
    format!("\x1b[{code}m{text}\x1b[0m")
}

const fn backpressure_count(s: &BackpressureState) -> u32 {
    (s.cpu_pressure as u32)
        + (s.ram_pressure as u32)
        + (s.io_pressure as u32)
        + (s.blackwell_vram_high as u32)
        + (s.gpu3090_busy as u32)
        + (s.human_gate_queue_high as u32)
}

// ============================================================================
// render_panel_compact
// ============================================================================

/// Render a single-line summary for `tail -f`-style watching or
/// status-bar embedding.
///
/// Format:
///
/// ```text
/// MS048: PSI/cpu=12.5% mem=22.0% io=5.0% | DCGM/bw=89.5% gpu=28.0% | hg=3 | degraded=1/3 firing=0/6
/// ```
#[must_use]
pub fn render_panel_compact(reading: &DriverReading) -> String {
    let m = &reading.measurements;
    let h = &reading.substrate_health;
    let s = &reading.state;
    format!(
        "MS048: PSI/cpu={:.1}% mem={:.1}% io={:.1}% | DCGM/bw={:.1}% gpu={:.1}% | hg={} | degraded={}/3 firing={}/6",
        m.cpu_psi * 100.0,
        m.mem_psi * 100.0,
        m.io_psi * 100.0,
        m.blackwell_vram_util * 100.0,
        m.gpu3090_util * 100.0,
        m.human_gate_queue_depth,
        h.degraded_count(),
        backpressure_count(s),
    )
}

// ============================================================================
// render_panel_from_audit_tail
// ============================================================================

/// Render the LATEST entry in the M01170 audit log as a panel.
/// Operator-facing "what was the last state?" view.
///
/// # Errors
///
/// Returns [`PanelError::Io`] on read failure;
/// [`PanelError::Parse`] on malformed JSONL.
pub fn render_panel_from_audit_tail(audit_path: &Path) -> Result<String, PanelError> {
    let text = fs::read_to_string(audit_path).map_err(|source| PanelError::Io {
        path: audit_path.to_path_buf(),
        source,
    })?;
    let last_line = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .next_back()
        .ok_or_else(|| PanelError::Parse {
            path: audit_path.to_path_buf(),
            reason: "audit log is empty".to_string(),
        })?;
    let entry: DriverAuditEntry =
        serde_json::from_str(last_line).map_err(|e| PanelError::Parse {
            path: audit_path.to_path_buf(),
            reason: format!("malformed json: {e}"),
        })?;
    Ok(render_panel(&entry.reading))
}

// ============================================================================
// render_panel_from_textfile
// ============================================================================

/// Render a panel from a live Prometheus textfile (the one the
/// M01168 exporter wrote). The textfile is reparsed line-by-line
/// to recover a `DriverReading` shape that drives the renderer.
///
/// This entry is useful when the binary that wants to render
/// doesn't have an M01170 audit log handy (e.g. operator one-shot
/// `selfdefctl scheduler status` against a host where the audit
/// log is on a different mount).
///
/// # Errors
///
/// Returns [`PanelError`] on IO or parse failure.
pub fn render_panel_from_textfile(textfile_path: &Path) -> Result<String, PanelError> {
    let text = fs::read_to_string(textfile_path).map_err(|source| PanelError::Io {
        path: textfile_path.to_path_buf(),
        source,
    })?;
    let reading = parse_textfile_into_reading(&text).map_err(|reason| PanelError::Parse {
        path: textfile_path.to_path_buf(),
        reason,
    })?;
    Ok(render_panel(&reading))
}

/// Parse a Prometheus textfile (produced by M01168) into a
/// `DriverReading` for rendering. Lossy: per-source reason text is
/// reconstructed from the substrate_status rows when present;
/// timestamps from last_run_unix.
///
/// Public so the selfdef-cli's `selfdefctl scheduler status` command
/// can reuse the parser for compact-mode + styled rendering paths
/// without round-tripping the rendered panel string.
///
/// # Errors
///
/// Returns a human-readable error string if parsing fails.
pub fn parse_textfile_into_reading(text: &str) -> Result<DriverReading, String> {
    let mut cpu_psi = 0.0_f32;
    let mut mem_psi = 0.0_f32;
    let mut io_psi = 0.0_f32;
    let mut blackwell_vram_util = 0.0_f32;
    let mut gpu3090_util = 0.0_f32;
    let mut human_gate_queue_depth = 0_u32;
    let mut cpu_pressure = false;
    let mut ram_pressure = false;
    let mut io_pressure = false;
    let mut blackwell_vram_high = false;
    let mut gpu3090_busy = false;
    let mut human_gate_queue_high = false;
    let mut psi_status = SourceStatus::Healthy;
    let mut dcgm_status = SourceStatus::Healthy;
    let mut human_gate_status = SourceStatus::Healthy;
    let mut last_run_unix = 0_u128;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Two line shapes:
        //   <name> <value>
        //   <name>{<labels>} <value>
        // Label values can contain spaces (e.g. reason="kernel < 4.20"),
        // so split-on-first-space breaks for labeled gauges. Split on
        // the closing '}' for labeled gauges, fall back to first-space
        // for bare gauges.
        let (name, labels, value) = if let Some(brace_open) = trimmed.find('{') {
            let Some(brace_close) = trimmed.find('}') else {
                continue;
            };
            let name = &trimmed[..brace_open];
            let labels = &trimmed[brace_open + 1..brace_close];
            let value = trimmed[brace_close + 1..].trim();
            (name, labels, value)
        } else {
            let Some((n, v)) = trimmed.split_once(' ') else {
                continue;
            };
            (n, "", v.trim())
        };
        match name {
            "selfdef_scheduler_cpu_psi" => cpu_psi = value.parse().unwrap_or(0.0),
            "selfdef_scheduler_mem_psi" => mem_psi = value.parse().unwrap_or(0.0),
            "selfdef_scheduler_io_psi" => io_psi = value.parse().unwrap_or(0.0),
            "selfdef_scheduler_blackwell_vram_util" => {
                blackwell_vram_util = value.parse().unwrap_or(0.0);
            }
            "selfdef_scheduler_gpu3090_util" => gpu3090_util = value.parse().unwrap_or(0.0),
            "selfdef_scheduler_human_gate_queue_depth" => {
                human_gate_queue_depth = value.parse().unwrap_or(0);
            }
            "selfdef_scheduler_cpu_pressure" => cpu_pressure = value == "1",
            "selfdef_scheduler_ram_pressure" => ram_pressure = value == "1",
            "selfdef_scheduler_io_pressure" => io_pressure = value == "1",
            "selfdef_scheduler_blackwell_vram_high" => blackwell_vram_high = value == "1",
            "selfdef_scheduler_gpu3090_busy" => gpu3090_busy = value == "1",
            "selfdef_scheduler_human_gate_queue_high" => human_gate_queue_high = value == "1",
            "selfdef_scheduler_last_run_unix" => {
                last_run_unix = value.parse::<u128>().unwrap_or(0) * 1_000_000;
            }
            "selfdef_scheduler_substrate_healthy" => {
                let source = parse_label_value(labels, "source").unwrap_or("");
                let healthy = value == "1";
                let target = match source {
                    "psi" => &mut psi_status,
                    "dcgm" => &mut dcgm_status,
                    "human_gate" => &mut human_gate_status,
                    _ => continue,
                };
                if !healthy && matches!(target, SourceStatus::Healthy) {
                    // Tentatively mark Unavailable; substrate_status
                    // row below (if present) refines reason text.
                    *target = SourceStatus::Unavailable(String::new());
                }
            }
            "selfdef_scheduler_substrate_status" => {
                let source = parse_label_value(labels, "source").unwrap_or("");
                let kind = parse_label_value(labels, "kind").unwrap_or("");
                let reason = parse_label_value(labels, "reason")
                    .unwrap_or("")
                    .to_string();
                let target = match source {
                    "psi" => &mut psi_status,
                    "dcgm" => &mut dcgm_status,
                    "human_gate" => &mut human_gate_status,
                    _ => continue,
                };
                *target = match kind {
                    "unavailable" => SourceStatus::Unavailable(reason),
                    "errored" => SourceStatus::Errored(reason),
                    _ => continue,
                };
            }
            _ => {}
        }
    }

    Ok(DriverReading {
        captured_at_unix_micros: last_run_unix,
        measurements: ResourceMeasurements {
            blackwell_vram_util,
            gpu3090_util,
            cpu_psi,
            mem_psi,
            io_psi,
            human_gate_queue_depth,
        },
        state: BackpressureState {
            blackwell_vram_high,
            gpu3090_busy,
            cpu_pressure,
            ram_pressure,
            io_pressure,
            human_gate_queue_high,
        },
        substrate_health: SubstrateHealth {
            psi_status,
            dcgm_status,
            human_gate_status,
        },
    })
}

/// Extract `key="value"` from a Prometheus label block. Returns
/// `None` if key absent. Handles simple unescaped values; the
/// escape format produced by `prometheus_exporter::escape_label_value`
/// would need an inverse, but for the panel renderer's purposes
/// the unescaped text is fine.
fn parse_label_value<'a>(labels: &'a str, key: &str) -> Option<&'a str> {
    for token in labels.split(',') {
        let trimmed = token.trim();
        let Some((k, v)) = trimmed.split_once('=') else {
            continue;
        };
        if k == key {
            return Some(v.trim().trim_matches('"'));
        }
    }
    None
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_reading() -> DriverReading {
        DriverReading {
            captured_at_unix_micros: 1_700_000_000_000_000,
            measurements: ResourceMeasurements {
                blackwell_vram_util: 0.895,
                gpu3090_util: 0.28,
                cpu_psi: 0.125,
                mem_psi: 0.22,
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

    // ---------------- render_panel ------------------------------------

    #[test]
    fn render_panel_contains_headline_and_all_sections() {
        let out = render_panel(&sample_reading());
        assert!(out.contains("MS048 Goldilocks Scheduler"));
        assert!(out.contains("SUBSTRATE"));
        assert!(out.contains("MEASUREMENT"));
        assert!(out.contains("Degraded substrates: 0/3"));
        assert!(out.contains("Backpressure surfaces firing: 0/6"));
    }

    #[test]
    fn render_panel_shows_per_substrate_status() {
        let out = render_panel(&sample_reading());
        // Three substrate rows by name.
        assert!(out.contains("PSI"));
        assert!(out.contains("DCGM"));
        assert!(out.contains("human-gate"));
    }

    #[test]
    fn render_panel_marks_degraded_substrate() {
        let mut r = sample_reading();
        r.substrate_health.dcgm_status = SourceStatus::Unavailable("kernel < 4.20".to_string());
        let out = render_panel(&r);
        assert!(out.contains("Unavailable: kernel < 4.20"));
        assert!(out.contains("Degraded substrates: 1/3"));
    }

    #[test]
    fn render_panel_marks_errored_substrate() {
        let mut r = sample_reading();
        r.substrate_health.psi_status = SourceStatus::Errored("driver crash".to_string());
        let out = render_panel(&r);
        assert!(out.contains("Errored: driver crash"));
    }

    #[test]
    fn render_panel_truncates_long_reason() {
        let long_reason = "x".repeat(200);
        let mut r = sample_reading();
        r.substrate_health.psi_status = SourceStatus::Errored(long_reason);
        let out = render_panel(&r);
        // Truncation suffix appears.
        assert!(out.contains('…'));
    }

    #[test]
    fn render_panel_renders_backpressure_fire_states() {
        let mut r = sample_reading();
        r.state.cpu_pressure = true;
        r.state.blackwell_vram_high = true;
        let out = render_panel(&r);
        assert!(out.contains("[fire]"));
        assert!(out.contains("Backpressure surfaces firing: 2/6"));
    }

    #[test]
    fn render_panel_includes_runtime_threshold_note() {
        let out = render_panel(&sample_reading());
        assert!(out.contains("scheduler.toml"));
    }

    #[test]
    fn render_panel_styled_ansi_includes_escape_codes() {
        let out = render_panel_styled(&sample_reading(), PanelStyle::AnsiColor);
        assert!(out.contains("\x1b["));
    }

    #[test]
    fn render_panel_styled_plain_no_escape_codes() {
        let out = render_panel_styled(&sample_reading(), PanelStyle::Plain);
        assert!(!out.contains("\x1b["));
    }

    // ---------------- render_panel_compact ----------------------------

    #[test]
    fn compact_summary_one_line() {
        let out = render_panel_compact(&sample_reading());
        assert_eq!(out.lines().count(), 1);
        assert!(out.starts_with("MS048:"));
        assert!(out.contains("cpu=12.5%"));
        assert!(out.contains("bw=89.5%"));
        assert!(out.contains("hg=3"));
        assert!(out.contains("degraded=0/3"));
    }

    // ---------------- render_panel_from_audit_tail -------------------

    #[test]
    fn audit_tail_renders_latest_entry() {
        use crate::decision_audit::emit_driver_reading;
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let mut r1 = sample_reading();
        r1.measurements.cpu_psi = 0.10;
        emit_driver_reading(&path, &r1, None).unwrap();
        let mut r2 = sample_reading();
        r2.measurements.cpu_psi = 0.42; // LATEST
        emit_driver_reading(&path, &r2, None).unwrap();
        let out = render_panel_from_audit_tail(&path).unwrap();
        // CPU PSI line shows 42.0%, not 10.0%.
        assert!(out.contains("42.0%"));
        assert!(!out.contains("10.0%"));
    }

    #[test]
    fn audit_tail_empty_file_is_parse_error() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        fs::write(&path, "").unwrap();
        let err = render_panel_from_audit_tail(&path).unwrap_err();
        assert!(matches!(err, PanelError::Parse { .. }));
    }

    #[test]
    fn audit_tail_missing_file_is_io_error() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("never-created.jsonl");
        let err = render_panel_from_audit_tail(&path).unwrap_err();
        assert!(matches!(err, PanelError::Io { .. }));
    }

    #[test]
    fn audit_tail_malformed_last_line_is_parse_error() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        fs::write(&path, "not json\n").unwrap();
        let err = render_panel_from_audit_tail(&path).unwrap_err();
        assert!(matches!(err, PanelError::Parse { .. }));
    }

    // ---------------- render_panel_from_textfile ---------------------

    #[test]
    fn textfile_round_trip_reproduces_panel_values() {
        use crate::prometheus_exporter::render_prometheus;
        let original = sample_reading();
        let prom = render_prometheus(&original);
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("scheduler.prom");
        fs::write(&path, prom).unwrap();
        let panel = render_panel_from_textfile(&path).unwrap();
        // The panel should reproduce the same percentages.
        assert!(panel.contains("12.5%")); // cpu_psi
        assert!(panel.contains("89.5%")); // blackwell_vram
    }

    #[test]
    fn textfile_with_degraded_substrate_carries_reason() {
        use crate::prometheus_exporter::render_prometheus;
        let mut original = sample_reading();
        original.substrate_health.psi_status =
            SourceStatus::Unavailable("kernel < 4.20".to_string());
        let prom = render_prometheus(&original);
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("scheduler.prom");
        fs::write(&path, prom).unwrap();
        let panel = render_panel_from_textfile(&path).unwrap();
        assert!(panel.contains("Unavailable: kernel < 4.20"));
        assert!(panel.contains("Degraded substrates: 1/3"));
    }

    #[test]
    fn textfile_missing_file_is_io_error() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("never.prom");
        let err = render_panel_from_textfile(&path).unwrap_err();
        assert!(matches!(err, PanelError::Io { .. }));
    }

    // ---------------- PanelStyle::detect ------------------------------

    #[test]
    fn decide_returns_plain_when_no_color_set() {
        assert_eq!(PanelStyle::decide(true, true), PanelStyle::Plain);
    }

    #[test]
    fn decide_returns_plain_when_non_terminal() {
        assert_eq!(PanelStyle::decide(false, false), PanelStyle::Plain);
    }

    #[test]
    fn decide_returns_ansi_when_terminal_and_no_color_unset() {
        assert_eq!(PanelStyle::decide(true, false), PanelStyle::AnsiColor);
    }

    // ---------------- parse_textfile_into_reading ---------------------

    #[test]
    fn parse_textfile_handles_comment_lines() {
        let text = "\
# HELP selfdef_scheduler_cpu_psi blah
# TYPE selfdef_scheduler_cpu_psi gauge
selfdef_scheduler_cpu_psi 0.2
";
        let r = parse_textfile_into_reading(text).unwrap();
        assert!((r.measurements.cpu_psi - 0.2).abs() < 1e-5);
    }

    #[test]
    fn parse_textfile_handles_substrate_status_with_labels() {
        let text = r#"selfdef_scheduler_substrate_healthy{source="psi"} 0
selfdef_scheduler_substrate_status{source="psi",kind="errored",reason="x"} 1
"#;
        let r = parse_textfile_into_reading(text).unwrap();
        assert!(matches!(
            r.substrate_health.psi_status,
            SourceStatus::Errored(_)
        ));
    }

    #[test]
    fn parse_label_value_finds_key() {
        let labels = r#"source="dcgm",kind="unavailable",reason="x""#;
        assert_eq!(parse_label_value(labels, "source"), Some("dcgm"));
        assert_eq!(parse_label_value(labels, "kind"), Some("unavailable"));
        assert_eq!(parse_label_value(labels, "reason"), Some("x"));
        assert_eq!(parse_label_value(labels, "missing"), None);
    }
}
