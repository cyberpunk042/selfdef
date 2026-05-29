//! selfdef-modules-textfile observer — contract test.
//!
//! Locks the shape of the new module-catalog observer unit, timer,
//! and wrapper shipped this commit. Sister to the existing M060
//! cli-mirror plus m060-chain plus four-watchdog doctor observer
//! contracts.
//!
//! The module catalog is a load-bearing IPS surface — operators need
//! Prometheus visibility into per-category drift (a hardening module
//! dropping below the expected count silently weakens the IPS spine).
//! This observer surfaces the catalog state to node_exporter on the
//! same 60s cadence as the sibling doctors.
//!
//! Pure file-level contract: the wrapper + 2 unit files are
//! include_str!()'d and grepped for the right clauses.

const SERVICE_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-modules-textfile.service",);
const TIMER_UNIT: &str = include_str!("../../../packaging/systemd/selfdef-modules-textfile.timer",);
const WRAPPER: &str = include_str!("../../../packaging/scripts/selfdef-modules-textfile.sh",);

// ──────────────────────────────────────────────── service unit tests

#[test]
fn service_invokes_the_wrapper_at_canonical_path() {
    assert!(
        SERVICE_UNIT.contains("ExecStart=/usr/share/selfdef/selfdef-modules-textfile.sh"),
        "service must invoke /usr/share/selfdef/selfdef-modules-textfile.sh"
    );
}

#[test]
fn service_writes_to_node_exporter_textfile_collector_dir() {
    assert!(
        SERVICE_UNIT.contains(
            "SELFDEF_MODULES_TEXTFILE_PATH=/var/lib/node_exporter/textfile_collector/selfdef-modules.prom"
        ),
        "service must export the textfile path env var matching the \
         node_exporter textfile_collector convention"
    );
}

#[test]
fn service_runs_as_selfdef_user_not_root() {
    assert!(SERVICE_UNIT.contains("User=selfdef"));
    assert!(SERVICE_UNIT.contains("Group=selfdef"));
}

#[test]
fn service_grants_write_only_to_textfile_collector() {
    assert!(
        SERVICE_UNIT.contains("ReadWritePaths=/var/lib/node_exporter/textfile_collector"),
        "service must restrict writes to the textfile_collector dir"
    );
    assert!(
        !SERVICE_UNIT.contains("ReadWritePaths=/var/lib/selfdef"),
        "service must NOT have write access to /var/lib/selfdef"
    );
}

#[test]
fn service_hardening_matches_sibling_units() {
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
            SERVICE_UNIT.contains(required),
            "service missing required hardening clause: {required}"
        );
    }
}

#[test]
fn service_timeout_caps_runtime() {
    assert!(SERVICE_UNIT.contains("TimeoutStartSec=30s"));
}

#[test]
fn service_treats_success_as_success_only() {
    // Unlike the doctor observers which use SuccessExitStatus=0 1 2
    // (WARN/CRITICAL are signals), the modules observer has no
    // severity ladder — module listing either succeeds or fails.
    assert!(
        SERVICE_UNIT.contains("SuccessExitStatus=0"),
        "service must declare SuccessExitStatus=0 (no severity ladder \
         here; modules list either enumerates or fails)"
    );
}

// ───────────────────────────────────────────────────────── timer tests

#[test]
fn timer_runs_every_60_seconds() {
    assert!(
        TIMER_UNIT.contains("OnUnitActiveSec=60s"),
        "timer cadence must be 60s; matches sibling doctor observers"
    );
}

#[test]
fn timer_has_offset_boot_delay() {
    // 120s offset — above cli-mirror 60s, m060 70s, four-watchdog 90s
    // so the 4 doctor timers stagger their first fire after boot.
    assert!(
        TIMER_UNIT.contains("OnBootSec=120s"),
        "timer must have a 120s offset boot delay (above all 3 sibling \
         doctor timers at 60s/70s/90s)"
    );
}

#[test]
fn timer_binds_to_the_service() {
    assert!(
        TIMER_UNIT.contains("Unit=selfdef-modules-textfile.service"),
        "timer's Unit= must point at the service"
    );
}

#[test]
fn timer_randomized_delay_for_fleet_decorrelation() {
    assert!(
        TIMER_UNIT.contains("RandomizedDelaySec="),
        "timer must declare RandomizedDelaySec for fleet-wide decorrelation"
    );
}

#[test]
fn timer_install_section_wantedby_timers_target() {
    assert!(TIMER_UNIT.contains("[Install]"));
    assert!(TIMER_UNIT.contains("WantedBy=timers.target"));
}

// ────────────────────────────────────────────── wrapper contract tests

#[test]
fn wrapper_has_shebang() {
    assert!(WRAPPER.starts_with("#!/bin/bash"));
}

#[test]
fn wrapper_uses_strict_mode() {
    assert!(
        WRAPPER.contains("set -euo pipefail"),
        "wrapper must use strict shell mode"
    );
}

#[test]
fn wrapper_calls_selfdefctl_modules_list_json() {
    assert!(
        WRAPPER.contains("\"modules\" \"list\" \"--json\""),
        "wrapper must read the structured JSON from selfdefctl modules list"
    );
}

#[test]
fn wrapper_uses_atomic_tempfile_rename() {
    assert!(WRAPPER.contains("mktemp"));
    assert!(WRAPPER.contains("mv -f"));
}

#[test]
fn wrapper_emits_failure_sentinel_when_selfdefctl_missing() {
    assert!(
        WRAPPER.contains("selfdef_modules_textfile_emit_failed"),
        "wrapper must emit a failure-sentinel gauge"
    );
    assert!(
        WRAPPER.contains("command -v selfdefctl"),
        "wrapper must check selfdefctl is on PATH before invoking"
    );
}

#[test]
fn wrapper_emits_all_canonical_gauges() {
    for required in [
        "selfdef_modules_total",
        "selfdef_modules_by_category",
        "selfdef_modules_by_phase",
        "selfdef_modules_last_run_unix",
        "selfdef_modules_textfile_emit_failed",
    ] {
        assert!(
            WRAPPER.contains(required),
            "wrapper must emit gauge {required}"
        );
    }
}

#[test]
fn wrapper_per_category_gauge_carries_category_label() {
    // Per-category gauge MUST carry the category label so Grafana
    // can group across the module families.
    assert!(
        WRAPPER.contains("category=\""),
        "per-category gauge must carry the category label"
    );
    assert!(
        WRAPPER.contains("phase=\""),
        "per-phase gauge must carry the phase label"
    );
}

#[test]
fn wrapper_validates_json_envelope_shape() {
    // Refuse to emit zeroed gauges from a malformed response —
    // same honest-offline discipline as the four-watchdog wrapper.
    assert!(
        WRAPPER.contains("type == \"array\""),
        "wrapper must validate the JSON envelope is an array before \
         emitting gauges"
    );
}

#[test]
fn wrapper_documents_honest_offline_contract() {
    // The wrapper's docstring MUST document the honest-offline
    // contract so operators understand the sentinel gauge.
    assert!(
        WRAPPER.contains("Honest-offline")
            || WRAPPER.contains("honest-offline")
            || WRAPPER.contains("Honest offline"),
        "wrapper docstring must document the honest-offline contract"
    );
}

#[test]
fn wrapper_supports_module_dir_override() {
    // Operators using a non-default modules directory MUST be able
    // to override via SELFDEF_MODULES_DIR.
    assert!(
        WRAPPER.contains("SELFDEF_MODULES_DIR"),
        "wrapper must honor SELFDEF_MODULES_DIR override env var"
    );
}
