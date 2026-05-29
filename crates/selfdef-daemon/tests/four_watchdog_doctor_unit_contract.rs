//! Four-watchdog-doctor systemd unit + timer + textfile wrapper —
//! contract test.
//!
//! Locks the shape of the new observer-side units (timer + service)
//! that drive the `four-watchdog-textfile.sh` wrapper on a 60s cadence.
//! Companion to the existing m060_cli_mirror_doctor_unit_contract.rs
//! and m060_chain_doctor_unit_contract.rs — same shape, same 3-tier
//! severity ladder, same atomic-write + textfile_collector convention.
//!
//! The four-watchdog set is the IPS spine per SECURITY.md and SDD-004
//! §"Four-watchdog set (IPS spine, MS046+MS047+MS044+MS048)" — drift
//! catching here protects the operator's observability surface for
//! the production-shipped runtime spine.
//!
//! No systemd / dpkg / shell execution here — the wrapper + both unit
//! files are include_str!()'d and grepped for the right clauses. Pure
//! file-level contract, runs in any Rust test environment.

const DOCTOR_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-four-watchdog-doctor.service");
const DOCTOR_TIMER: &str =
    include_str!("../../../packaging/systemd/selfdef-four-watchdog-doctor.timer");
const WRAPPER: &str = include_str!("../../../packaging/scripts/four-watchdog-textfile.sh");

// ───────────────────────────────────────────────────── service unit tests

#[test]
fn doctor_service_invokes_the_wrapper_at_canonical_path() {
    // The wrapper ships at /usr/share/selfdef/four-watchdog-textfile.sh
    // via the Cargo.toml deb-assets row (this commit). The service
    // unit MUST invoke it from that canonical path — drift here means
    // the wrapper exists but the unit calls a missing binary.
    assert!(
        DOCTOR_UNIT.contains("ExecStart=/usr/share/selfdef/four-watchdog-textfile.sh"),
        "doctor service must invoke /usr/share/selfdef/four-watchdog-textfile.sh"
    );
}

#[test]
fn doctor_service_writes_to_node_exporter_textfile_collector_dir() {
    // The canonical textfile_collector path. Drift here = a stock
    // Prometheus + node_exporter setup wouldn't pick the metric up.
    assert!(
        DOCTOR_UNIT.contains(
            "SELFDEF_FOUR_WATCHDOG_TEXTFILE_PATH=/var/lib/node_exporter/textfile_collector/selfdef-four-watchdog.prom"
        ),
        "service must export the textfile path env var matching the \
         node_exporter textfile_collector convention"
    );
}

#[test]
fn doctor_service_treats_warn_and_fail_exit_as_success() {
    // Same exit-code contract as the cli-mirror + m060 doctors: WARN/
    // CRITICAL are signals captured in the metric, not unit failure.
    assert!(
        DOCTOR_UNIT.contains("SuccessExitStatus=0 1 2"),
        "service must declare SuccessExitStatus=0 1 2 — the wrapper's \
         severity-ladder exit codes are the signal, not unit failure"
    );
}

#[test]
fn doctor_service_runs_as_selfdef_user_not_root() {
    assert!(DOCTOR_UNIT.contains("User=selfdef"));
    assert!(DOCTOR_UNIT.contains("Group=selfdef"));
}

#[test]
fn doctor_service_grants_write_only_to_textfile_collector() {
    // ReadWritePaths MUST contain the textfile_collector + ONLY that.
    // The wrapper does not need write access to anything else; sealing
    // that off keeps the observer's blast radius minimal.
    assert!(
        DOCTOR_UNIT.contains("ReadWritePaths=/var/lib/node_exporter/textfile_collector"),
        "service must restrict writes to the textfile_collector dir"
    );
    assert!(
        !DOCTOR_UNIT.contains("ReadWritePaths=/var/lib/selfdef"),
        "service must NOT have write access to /var/lib/selfdef"
    );
}

#[test]
fn doctor_service_hardening_matches_sibling_units() {
    // Same hardening posture as the sibling doctor services — drift
    // here means the four-watchdog observer is laxer than its peers.
    for required in [
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "ProtectKernelTunables=true",
        "ProtectKernelLogs=true",
        "ProtectControlGroups=true",
        "LockPersonality=true",
        "RestrictNamespaces=true",
        "RestrictRealtime=true",
        "RestrictSUIDSGID=true",
        "SystemCallArchitectures=native",
        "PrivateNetwork=true",
        "RestrictAddressFamilies=AF_UNIX",
    ] {
        assert!(
            DOCTOR_UNIT.contains(required),
            "service missing required hardening clause: {required}"
        );
    }
}

#[test]
fn doctor_service_timeout_caps_runtime() {
    assert!(
        DOCTOR_UNIT.contains("TimeoutStartSec=30s"),
        "service must declare a TimeoutStartSec ceiling"
    );
}

// ───────────────────────────────────────────────────────── timer tests

#[test]
fn doctor_timer_runs_every_60_seconds() {
    // Same cadence as the sibling cli-mirror + m060 doctor timers —
    // Prometheus alert rules tuned to this interval.
    assert!(
        DOCTOR_TIMER.contains("OnUnitActiveSec=60s"),
        "timer cadence must be 60s; alert rules tuned to this interval"
    );
}

#[test]
fn doctor_timer_has_offset_boot_delay() {
    // 90s offset so it doesn't fire at the same boot moment as the
    // sibling -doctor timers (which use 60s or 70s).
    assert!(
        DOCTOR_TIMER.contains("OnBootSec=90s"),
        "timer must have an offset boot delay to avoid sibling collision"
    );
}

#[test]
fn doctor_timer_binds_to_the_doctor_service() {
    assert!(
        DOCTOR_TIMER.contains("Unit=selfdef-four-watchdog-doctor.service"),
        "timer's Unit= must point at the four-watchdog-doctor service"
    );
}

#[test]
fn doctor_timer_randomized_delay_for_fleet_decorrelation() {
    // Same RandomizedDelaySec convention as the sibling timers so a
    // fleet of hosts doesn't synchronize their write moments.
    assert!(
        DOCTOR_TIMER.contains("RandomizedDelaySec="),
        "timer must declare RandomizedDelaySec for fleet-wide decorrelation"
    );
}

#[test]
fn doctor_timer_install_section_wantedby_timers_target() {
    assert!(DOCTOR_TIMER.contains("[Install]"));
    assert!(DOCTOR_TIMER.contains("WantedBy=timers.target"));
}

// ──────────────────────────────────────────────── wrapper contract tests

#[test]
fn wrapper_has_shebang() {
    assert!(
        WRAPPER.starts_with("#!/bin/bash"),
        "wrapper must declare bash shebang"
    );
}

#[test]
fn wrapper_uses_strict_mode() {
    assert!(
        WRAPPER.contains("set -euo pipefail"),
        "wrapper must use strict shell mode — pipeline failures must \
         surface as wrapper failures so monitoring can react"
    );
}

#[test]
fn wrapper_calls_selfdefctl_alerts_json() {
    assert!(
        WRAPPER.contains("selfdefctl alerts --json"),
        "wrapper must read the structured JSON from selfdefctl alerts \
         — drift to text parsing would silently break on output format \
         changes"
    );
}

#[test]
fn wrapper_uses_atomic_tempfile_rename() {
    // Atomic write pattern: mktemp + rename — node_exporter never sees
    // a half-written file. Same pattern as the m060 producers.
    assert!(
        WRAPPER.contains("mktemp"),
        "wrapper must use mktemp to stage the textfile"
    );
    assert!(
        WRAPPER.contains("mv -f"),
        "wrapper must atomically rename the staging file into place"
    );
}

#[test]
fn wrapper_emits_failure_sentinel_when_selfdefctl_missing() {
    // Honest-offline contract: when selfdefctl is not on PATH, write
    // a sentinel gauge so monitoring can distinguish "no data" from
    // "all healthy". NEVER silently emit a zeroed textfile.
    assert!(
        WRAPPER.contains("selfdef_four_watchdog_textfile_emit_failed"),
        "wrapper must emit a failure-sentinel gauge on selfdefctl unavailability"
    );
    assert!(
        WRAPPER.contains("command -v selfdefctl"),
        "wrapper must check selfdefctl is on PATH before invoking"
    );
}

#[test]
fn wrapper_emits_all_canonical_gauges() {
    // The 4 canonical metric series the alert rules + Grafana panels
    // depend on. Drift in metric names = silent observability outage.
    for required in [
        "selfdef_four_watchdog_worst_severity",
        "selfdef_four_watchdog_severity",
        "selfdef_four_watchdog_last_run_unix",
        "selfdef_four_watchdog_textfile_emit_failed",
    ] {
        assert!(
            WRAPPER.contains(required),
            "wrapper must emit gauge {required} — Prometheus rules \
             depend on this exact metric name"
        );
    }
}

#[test]
fn wrapper_emits_severity_help_with_canonical_ladder() {
    // The 0=OK / 1=WARN / 2=CRITICAL ladder MUST be documented in the
    // HELP line so an operator inspecting /metrics knows how to read
    // the gauge. Same ladder convention as the cli-mirror + m060
    // doctors.
    assert!(
        WRAPPER.contains("0=OK") && WRAPPER.contains("1=WARN") && WRAPPER.contains("2=CRITICAL"),
        "HELP line must document the 0/1/2/-1 severity ladder verbatim"
    );
}

#[test]
fn wrapper_severity_to_int_handles_all_canonical_states() {
    // The 4 states the daemon emits: ok / warn / critical / unknown.
    // The wrapper MUST handle all 4 explicitly so a fresh state slot
    // doesn't silently fall through as -1.
    for state in ["ok)", "warn)", "critical)", "unknown)"] {
        assert!(
            WRAPPER.contains(state),
            "wrapper severity_to_int must handle state {state} explicitly"
        );
    }
}

#[test]
fn wrapper_carries_per_alert_labels_for_grafana_grouping() {
    // The per-alert gauge MUST carry alert/ms/series labels so Grafana
    // can group across milestone families + render per-series panels.
    // Drift = the milestone-grouped dashboards stop working.
    assert!(
        WRAPPER.contains("alert=") && WRAPPER.contains("ms=") && WRAPPER.contains("series="),
        "per-alert gauge must carry alert/ms/series labels for Grafana grouping"
    );
}

#[test]
fn wrapper_exit_code_mirrors_severity_ladder() {
    // The wrapper's exit codes (0/1/2) MUST mirror the severity ladder
    // so systemd SuccessExitStatus=0 1 2 captures all healthy paths
    // and signal-level failures still propagate as unit failure.
    assert!(WRAPPER.contains("exit 0"));
    assert!(WRAPPER.contains("exit 1"));
    assert!(WRAPPER.contains("exit 2"));
}

#[test]
fn wrapper_documents_ips_spine_anchor() {
    // The wrapper documents what it observes — drift here = operators
    // don't know which production milestones this textfile maps to.
    assert!(
        WRAPPER.contains("MS046")
            && WRAPPER.contains("MS047")
            && WRAPPER.contains("MS044")
            && WRAPPER.contains("MS048"),
        "wrapper docstring must anchor to the 4 IPS-spine milestones"
    );
}
