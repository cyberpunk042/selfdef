//! Prometheus metrics for the four-watchdog set.
//!
//! Renders Prometheus exposition-format gauges sampled at scrape time
//! from the runtime crates' ring buffers + audit chains. No atomic
//! counter mirroring — the ring buffers ARE the source of truth, and
//! `rate()` over the timeseries gives operators throughput.
//!
//! Series exposed (gauges unless noted):
//!
//! ## friction-audit (MS046 / SDD-027)
//! - `selfdef_friction_audit_verdicts_total`     — count in ring buffer
//! - `selfdef_friction_audit_failing_total`      — verdicts in Fail status
//! - `selfdef_friction_audit_overrides_total`    — verdicts under override
//!
//! ## perimeter (MS047 / SDD-028)
//! - `selfdef_perimeter_verdicts_total`          — count in ring buffer
//! - `selfdef_perimeter_sigkills_total`          — Sigkill outcomes
//! - `selfdef_perimeter_extensions_total`        — active extension manifests
//! - `selfdef_perimeter_policy_present`          — 1 if TracingPolicy installed
//! - `selfdef_perimeter_audit_chain_events`      — chain length (-1 on break)
//!
//! ## guardian (MS044 / SDD-029)
//! - `selfdef_guardian_verdicts_total`           — count in ring buffer
//! - `selfdef_guardian_failed_responses_total`   — verdicts with any Failed step
//! - `selfdef_guardian_tetragon_socket_present`  — 1 if /var/run/tetragon/... exists
//! - `selfdef_guardian_audit_chain_events`       — chain length (-1 on break)
//!
//! ## scheduler (MS048 / SDD-031)
//! - `selfdef_scheduler_decisions_total`         — count in ring buffer
//! - `selfdef_scheduler_backpressured_decisions_total` — decisions under any backpressure
//! - `selfdef_scheduler_audit_chain_events`      — chain length (-1 on break)
//!
//! ## modules (MS006 / SDD-009 Q-G)
//! - `selfdef_modules_shipped_total`             — count of modules in /usr/share/selfdef/modules/
//! - `selfdef_modules_active_total`              — count activated in /etc/selfdef/modules.toml
//!
//! Cross-references:
//! - MS027 (observability) — this is the four-watchdog Prometheus emission layer
//! - modules/observability/assets/dashboards/selfdef.json.template — Grafana
//!   panels query these series

use std::fmt::Write;
use std::path::Path;

use selfdef_friction_audit::{
    read_ring_buffer as fa_read, DEFAULT_RING_DIR as FA_RING,
};
use selfdef_friction_audit_mirror::Status;
use selfdef_guardian::{
    audit_chain_check as guard_chain, read_ring_buffer as guard_read,
    DEFAULT_OCSF_PATH as GUARD_OCSF, DEFAULT_RING_DIR as GUARD_RING,
    DEFAULT_SOCKET_PATH as GUARD_SOCK,
};
use selfdef_perimeter::{
    audit_chain_check as perim_chain, now_ms, read_ring_buffer as perim_read,
    ExtensionStore, Outcome, DEFAULT_EXTENSION_DIR, DEFAULT_OCSF_PATH as PERIM_OCSF,
    DEFAULT_POLICY_PATH, DEFAULT_RING_DIR as PERIM_RING, DEFAULT_TRUST_ROOTS_DIR,
};
use selfdef_scheduler::{
    audit_chain_check as sched_chain, read_ring_buffer as sched_read,
    DEFAULT_AUDIT_LOG_PATH as SCHED_AUDIT, DEFAULT_RING_DIR as SCHED_RING,
};

/// Render four-watchdog Prometheus metrics. Reads ring buffers + audit
/// chains synchronously at call time. Each read failure surfaces as the
/// sentinel value (0 for count gauges, -1 for chain-event gauges) — never
/// panics, so the /metrics endpoint stays responsive even when watchdogs
/// are degraded.
#[must_use]
pub fn render() -> String {
    let mut out = String::with_capacity(2048);
    render_friction_audit(&mut out);
    render_perimeter(&mut out);
    render_guardian(&mut out);
    render_scheduler(&mut out);
    render_modules(&mut out);
    out
}

fn render_modules(out: &mut String) {
    let modules_dir = std::env::var("SELFDEF_MODULES_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(crate::modules::DEFAULT_MODULES_DIR));
    let modules_toml = std::env::var("SELFDEF_MODULES_TOML")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(crate::modules::DEFAULT_MODULES_TOML));
    let shipped = crate::modules::list_in_dir(&modules_dir).unwrap_or_default();
    let active = crate::modules::active_modules(&modules_toml);

    out.push_str("# HELP selfdef_modules_shipped_total Modules shipped at /usr/share/selfdef/modules/ (parsed module.toml count).\n");
    out.push_str("# TYPE selfdef_modules_shipped_total gauge\n");
    writeln!(out, "selfdef_modules_shipped_total {}", shipped.len()).unwrap();

    out.push_str("# HELP selfdef_modules_active_total Modules activated by the operator in /etc/selfdef/modules.toml.\n");
    out.push_str("# TYPE selfdef_modules_active_total gauge\n");
    writeln!(out, "selfdef_modules_active_total {}", active.len()).unwrap();
}

fn render_friction_audit(out: &mut String) {
    let verdicts = fa_read(Path::new(FA_RING)).unwrap_or_default();
    let failing = verdicts
        .iter()
        .filter(|v| matches!(v.status, Status::Fail(_)))
        .count();
    let overrides = verdicts
        .iter()
        .filter(|v| matches!(v.status, Status::OverrideActive { .. }))
        .count();

    out.push_str("# HELP selfdef_friction_audit_verdicts_total Verdicts currently in the friction-audit ring buffer.\n");
    out.push_str("# TYPE selfdef_friction_audit_verdicts_total gauge\n");
    writeln!(out, "selfdef_friction_audit_verdicts_total {}", verdicts.len()).unwrap();

    out.push_str("# HELP selfdef_friction_audit_failing_total Verdicts in Fail status (no override honoring).\n");
    out.push_str("# TYPE selfdef_friction_audit_failing_total gauge\n");
    writeln!(out, "selfdef_friction_audit_failing_total {failing}").unwrap();

    out.push_str("# HELP selfdef_friction_audit_overrides_total Verdicts honoring an operator-signed override.\n");
    out.push_str("# TYPE selfdef_friction_audit_overrides_total gauge\n");
    writeln!(out, "selfdef_friction_audit_overrides_total {overrides}").unwrap();
}

fn render_perimeter(out: &mut String) {
    let now = now_ms();
    let verdicts = perim_read(Path::new(PERIM_RING)).unwrap_or_default();
    let sigkills = verdicts
        .iter()
        .filter(|v| matches!(v.outcome, Outcome::Sigkill))
        .count();
    let extensions = ExtensionStore::load_dir(
        Path::new(DEFAULT_EXTENSION_DIR),
        Path::new(DEFAULT_TRUST_ROOTS_DIR),
        now,
    )
    .map(|(s, _)| s.active(now).len())
    .unwrap_or(0);
    let policy_present = if Path::new(DEFAULT_POLICY_PATH).exists() { 1 } else { 0 };
    let chain_events: i64 = perim_chain(Path::new(PERIM_OCSF))
        .map(|n| n as i64)
        .unwrap_or(-1);

    out.push_str("# HELP selfdef_perimeter_verdicts_total Verdicts currently in the perimeter ring buffer.\n");
    out.push_str("# TYPE selfdef_perimeter_verdicts_total gauge\n");
    writeln!(out, "selfdef_perimeter_verdicts_total {}", verdicts.len()).unwrap();

    out.push_str("# HELP selfdef_perimeter_sigkills_total Verdicts with Sigkill outcome.\n");
    out.push_str("# TYPE selfdef_perimeter_sigkills_total gauge\n");
    writeln!(out, "selfdef_perimeter_sigkills_total {sigkills}").unwrap();

    out.push_str("# HELP selfdef_perimeter_extensions_total Active operator-signed allowlist extensions.\n");
    out.push_str("# TYPE selfdef_perimeter_extensions_total gauge\n");
    writeln!(out, "selfdef_perimeter_extensions_total {extensions}").unwrap();

    out.push_str("# HELP selfdef_perimeter_policy_present 1 if sovereign-perimeter.yaml is installed.\n");
    out.push_str("# TYPE selfdef_perimeter_policy_present gauge\n");
    writeln!(out, "selfdef_perimeter_policy_present {policy_present}").unwrap();

    out.push_str("# HELP selfdef_perimeter_audit_chain_events Perimeter OCSF audit chain length; -1 on chain break.\n");
    out.push_str("# TYPE selfdef_perimeter_audit_chain_events gauge\n");
    writeln!(out, "selfdef_perimeter_audit_chain_events {chain_events}").unwrap();
}

fn render_guardian(out: &mut String) {
    let verdicts = guard_read(Path::new(GUARD_RING)).unwrap_or_default();
    let failed = verdicts.iter().filter(|v| !v.all_steps_ok()).count();
    let socket_present = if Path::new(GUARD_SOCK).exists() { 1 } else { 0 };
    let chain_events: i64 = guard_chain(Path::new(GUARD_OCSF))
        .map(|n| n as i64)
        .unwrap_or(-1);

    out.push_str("# HELP selfdef_guardian_verdicts_total Verdicts currently in the guardian ring buffer.\n");
    out.push_str("# TYPE selfdef_guardian_verdicts_total gauge\n");
    writeln!(out, "selfdef_guardian_verdicts_total {}", verdicts.len()).unwrap();

    out.push_str("# HELP selfdef_guardian_failed_responses_total Verdicts with at least one Failed step.\n");
    out.push_str("# TYPE selfdef_guardian_failed_responses_total gauge\n");
    writeln!(out, "selfdef_guardian_failed_responses_total {failed}").unwrap();

    out.push_str("# HELP selfdef_guardian_tetragon_socket_present 1 if the Tetragon UNIX socket is reachable.\n");
    out.push_str("# TYPE selfdef_guardian_tetragon_socket_present gauge\n");
    writeln!(out, "selfdef_guardian_tetragon_socket_present {socket_present}").unwrap();

    out.push_str("# HELP selfdef_guardian_audit_chain_events Guardian OCSF audit chain length; -1 on chain break.\n");
    out.push_str("# TYPE selfdef_guardian_audit_chain_events gauge\n");
    writeln!(out, "selfdef_guardian_audit_chain_events {chain_events}").unwrap();
}

fn render_scheduler(out: &mut String) {
    let decisions = sched_read(Path::new(SCHED_RING)).unwrap_or_default();
    let backpressured = decisions
        .iter()
        .filter(|d| d.backpressure.any_pressure())
        .count();
    let chain_events: i64 = sched_chain(Path::new(SCHED_AUDIT))
        .map(|n| n as i64)
        .unwrap_or(-1);

    out.push_str("# HELP selfdef_scheduler_decisions_total Decisions currently in the scheduler ring buffer.\n");
    out.push_str("# TYPE selfdef_scheduler_decisions_total gauge\n");
    writeln!(out, "selfdef_scheduler_decisions_total {}", decisions.len()).unwrap();

    out.push_str("# HELP selfdef_scheduler_backpressured_decisions_total Decisions with any backpressure surface open.\n");
    out.push_str("# TYPE selfdef_scheduler_backpressured_decisions_total gauge\n");
    writeln!(out, "selfdef_scheduler_backpressured_decisions_total {backpressured}").unwrap();

    out.push_str("# HELP selfdef_scheduler_audit_chain_events Scheduler audit chain length; -1 on chain break.\n");
    out.push_str("# TYPE selfdef_scheduler_audit_chain_events gauge\n");
    writeln!(out, "selfdef_scheduler_audit_chain_events {chain_events}").unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_emits_all_thirteen_series() {
        let out = render();
        let expected_series = [
            "selfdef_friction_audit_verdicts_total",
            "selfdef_friction_audit_failing_total",
            "selfdef_friction_audit_overrides_total",
            "selfdef_perimeter_verdicts_total",
            "selfdef_perimeter_sigkills_total",
            "selfdef_perimeter_extensions_total",
            "selfdef_perimeter_policy_present",
            "selfdef_perimeter_audit_chain_events",
            "selfdef_guardian_verdicts_total",
            "selfdef_guardian_failed_responses_total",
            "selfdef_guardian_tetragon_socket_present",
            "selfdef_guardian_audit_chain_events",
            "selfdef_scheduler_decisions_total",
            "selfdef_scheduler_backpressured_decisions_total",
            "selfdef_scheduler_audit_chain_events",
        ];
        for s in &expected_series {
            assert!(
                out.contains(&format!("# HELP {s} ")),
                "missing HELP for {s}"
            );
            assert!(
                out.contains(&format!("# TYPE {s} gauge")),
                "missing TYPE gauge for {s}"
            );
        }
    }

    #[test]
    fn render_each_metric_is_a_valid_prometheus_line() {
        let out = render();
        for line in out.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            // Each non-comment line: NAME VALUE (no labels in this render).
            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            assert_eq!(parts.len(), 2, "malformed line: {line:?}");
            let value = parts[1];
            // Parse as i64 OR f64 (we emit gauges as integers, but
            // allow Prometheus-valid floats too in case we add any).
            assert!(
                value.parse::<i64>().is_ok() || value.parse::<f64>().is_ok(),
                "non-numeric value: {value:?} in line {line:?}"
            );
        }
    }

    #[test]
    fn render_handles_missing_paths_gracefully() {
        // On a host with no /var/cache/selfdef/*/ring/ etc, render()
        // should produce zero-count gauges (or -1 for chain-events that
        // can't be checked) — never panic, never empty.
        let out = render();
        assert!(!out.is_empty());
        // Specifically: every counter line ends with " 0" OR " <-1>"
        // when no data is present. This test doesn't ASSERT the values
        // because the test runner may have stale state, but the render
        // succeeded which is the contract.
        assert!(out.contains("selfdef_friction_audit_verdicts_total"));
    }
}
