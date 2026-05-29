//! selfdef-systemd-units-textfile observer — contract test.
//!
//! Locks the 8th sibling textfile observer shipped this commit.
//! Surfaces per-state counts (active / inactive / failed /
//! activating) for ALL selfdef-prefixed systemd units so operators
//! detect silent unit failures.

const SERVICE_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-systemd-units-textfile.service");
const TIMER_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-systemd-units-textfile.timer");
const WRAPPER: &str = include_str!("../../../packaging/scripts/selfdef-systemd-units-textfile.sh");

// ──────────────────────────────────────────────── service unit tests

#[test]
fn service_invokes_the_wrapper_at_canonical_path() {
    assert!(
        SERVICE_UNIT.contains("ExecStart=/usr/share/selfdef/selfdef-systemd-units-textfile.sh")
    );
}

#[test]
fn service_writes_to_node_exporter_textfile_collector_dir() {
    assert!(SERVICE_UNIT.contains(
        "SELFDEF_SYSTEMD_UNITS_TEXTFILE_PATH=/var/lib/node_exporter/textfile_collector/selfdef-systemd-units.prom"
    ));
}

#[test]
fn service_default_prefix_selfdef_dash() {
    assert!(SERVICE_UNIT.contains("SELFDEF_SYSTEMD_UNITS_PREFIX=selfdef-"));
}

#[test]
fn service_runs_as_selfdef_user_not_root() {
    assert!(SERVICE_UNIT.contains("User=selfdef"));
    assert!(SERVICE_UNIT.contains("Group=selfdef"));
}

#[test]
fn service_grants_write_only_to_textfile_collector() {
    assert!(SERVICE_UNIT.contains("ReadWritePaths=/var/lib/node_exporter/textfile_collector"));
    assert!(!SERVICE_UNIT.contains("ReadWritePaths=/var/lib/selfdef"));
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
    assert!(SERVICE_UNIT.contains("SuccessExitStatus=0"));
}

// ───────────────────────────────────────────────────── timer tests

#[test]
fn timer_runs_every_60_seconds() {
    assert!(TIMER_UNIT.contains("OnUnitActiveSec=60s"));
}

#[test]
fn timer_has_240s_offset_boot_delay() {
    // 8th and latest observer timer — above the 7 sibling timers.
    assert!(
        TIMER_UNIT.contains("OnBootSec=240s"),
        "timer must have 240s offset (8th distinct above 7 siblings)"
    );
}

#[test]
fn timer_binds_to_the_service() {
    assert!(TIMER_UNIT.contains("Unit=selfdef-systemd-units-textfile.service"));
}

#[test]
fn timer_randomized_delay_for_fleet_decorrelation() {
    assert!(TIMER_UNIT.contains("RandomizedDelaySec="));
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
    assert!(WRAPPER.contains("set -euo pipefail"));
}

#[test]
fn wrapper_uses_systemctl_list_units_all() {
    // The --all flag is load-bearing — without it, inactive units
    // are hidden + we miss failed unit detection.
    assert!(
        WRAPPER.contains("systemctl list-units --all"),
        "wrapper must use --all so inactive + failed units are counted"
    );
}

#[test]
fn wrapper_filters_to_service_and_timer_types() {
    assert!(
        WRAPPER.contains("--type=service,timer"),
        "wrapper must filter to service + timer types (selfdef ships both)"
    );
}

#[test]
fn wrapper_uses_atomic_tempfile_rename() {
    assert!(WRAPPER.contains("mktemp"));
    assert!(WRAPPER.contains("mv -f"));
}

#[test]
fn wrapper_emits_failure_sentinel_when_systemctl_missing() {
    assert!(WRAPPER.contains("selfdef_systemd_units_textfile_emit_failed"));
    assert!(WRAPPER.contains("command -v systemctl"));
}

#[test]
fn wrapper_emits_all_canonical_gauges() {
    for required in [
        "selfdef_systemd_units_total",
        "selfdef_systemd_units_active",
        "selfdef_systemd_units_inactive",
        "selfdef_systemd_units_failed",
        "selfdef_systemd_units_activating",
        "selfdef_systemd_units_other",
        "selfdef_systemd_units_last_run_unix",
        "selfdef_systemd_units_textfile_emit_failed",
    ] {
        assert!(
            WRAPPER.contains(required),
            "wrapper must emit gauge {required}"
        );
    }
}

#[test]
fn wrapper_per_gauge_carries_prefix_label() {
    assert!(
        WRAPPER.contains("prefix=\""),
        "per-state gauges must carry the prefix label for operator filtering"
    );
}

#[test]
fn wrapper_handles_all_canonical_active_states() {
    // The wrapper MUST handle the 5 canonical systemd ActiveState
    // values: active / inactive / failed / activating / and a
    // catch-all for deactivating/reloading.
    for state in ["active)", "inactive)", "failed)", "activating)"] {
        assert!(
            WRAPPER.contains(state),
            "wrapper must handle ActiveState {state}"
        );
    }
}

#[test]
fn wrapper_documents_honest_offline_contract() {
    assert!(WRAPPER.contains("Honest-offline") || WRAPPER.contains("honest-offline"),);
}

#[test]
fn wrapper_documents_silent_unit_failure_purpose() {
    // Document why systemd-unit health is IPS-load-bearing —
    // operator-actionable context.
    assert!(
        WRAPPER.contains("silent"),
        "wrapper docstring must explain silent-unit-failure detection purpose"
    );
}

#[test]
fn wrapper_supports_prefix_override() {
    assert!(
        WRAPPER.contains("SELFDEF_SYSTEMD_UNITS_PREFIX"),
        "wrapper must honor SELFDEF_SYSTEMD_UNITS_PREFIX override env"
    );
}
