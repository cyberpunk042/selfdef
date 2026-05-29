//! selfdef-auth-events-textfile observer — contract test.
//!
//! Locks the shape of the new auth-event observer unit, timer, and
//! wrapper shipped this commit. Sister to the 6 existing observer
//! contracts. Surfaces brute-force + privilege-escalation attempts
//! to Prometheus before they succeed.

const SERVICE_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-auth-events-textfile.service");
const TIMER_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-auth-events-textfile.timer");
const WRAPPER: &str = include_str!("../../../packaging/scripts/selfdef-auth-events-textfile.sh");

// ──────────────────────────────────────────────── service unit tests

#[test]
fn service_invokes_the_wrapper_at_canonical_path() {
    assert!(SERVICE_UNIT.contains("ExecStart=/usr/share/selfdef/selfdef-auth-events-textfile.sh"));
}

#[test]
fn service_writes_to_node_exporter_textfile_collector_dir() {
    assert!(SERVICE_UNIT.contains(
        "SELFDEF_AUTH_EVENTS_TEXTFILE_PATH=/var/lib/node_exporter/textfile_collector/selfdef-auth-events.prom"
    ));
}

#[test]
fn service_default_window_5m() {
    assert!(
        SERVICE_UNIT.contains("SELFDEF_AUTH_EVENTS_WINDOW=5m"),
        "service must default to a 5m rolling window"
    );
}

#[test]
fn service_runs_as_selfdef_user_not_root() {
    assert!(SERVICE_UNIT.contains("User=selfdef"));
    assert!(SERVICE_UNIT.contains("Group=selfdef"));
}

#[test]
fn service_documents_journal_access_requirement() {
    // The selfdef user needs systemd-journal supplementary group OR
    // world-readable journal to read auth events. Drift here =
    // operators install the unit but it silently fails to read
    // auth events with no obvious cause.
    assert!(
        SERVICE_UNIT.contains("systemd-journal") || SERVICE_UNIT.contains("SupplementaryGroups"),
        "service must document the systemd-journal access requirement"
    );
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
fn timer_has_210s_offset_boot_delay() {
    // 7th and latest observer timer — above the 6 sibling timers at
    // 60s/70s/90s/120s/150s/180s.
    assert!(
        TIMER_UNIT.contains("OnBootSec=210s"),
        "timer must have 210s offset (7th distinct above 6 siblings)"
    );
}

#[test]
fn timer_binds_to_the_service() {
    assert!(TIMER_UNIT.contains("Unit=selfdef-auth-events-textfile.service"));
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
fn wrapper_calls_journalctl_for_auth_facility() {
    assert!(
        WRAPPER.contains("journalctl") && WRAPPER.contains("--facility=auth,authpriv"),
        "wrapper must read journal auth + authpriv facilities"
    );
}

#[test]
fn wrapper_uses_atomic_tempfile_rename() {
    assert!(WRAPPER.contains("mktemp"));
    assert!(WRAPPER.contains("mv -f"));
}

#[test]
fn wrapper_emits_failure_sentinel_when_journalctl_missing() {
    assert!(WRAPPER.contains("selfdef_auth_events_textfile_emit_failed"));
    assert!(
        WRAPPER.contains("command -v journalctl"),
        "wrapper must check journalctl is on PATH"
    );
}

#[test]
fn wrapper_emits_all_canonical_gauges() {
    for required in [
        "selfdef_auth_events_login_failures",
        "selfdef_auth_events_login_successes",
        "selfdef_auth_events_sudo_invocations",
        "selfdef_auth_events_ssh_invalid_users",
        "selfdef_auth_events_ssh_refused_keys",
        "selfdef_auth_events_total",
        "selfdef_auth_events_last_run_unix",
        "selfdef_auth_events_textfile_emit_failed",
    ] {
        assert!(
            WRAPPER.contains(required),
            "wrapper must emit gauge {required}"
        );
    }
}

#[test]
fn wrapper_per_gauge_carries_window_label() {
    // The 6 per-window gauges MUST carry the window= label so
    // operators can grep for the canonical 5m window vs operator
    // overrides.
    assert!(
        WRAPPER.contains("window=\""),
        "per-window gauges must carry the window label"
    );
}

#[test]
fn wrapper_pattern_matches_canonical_auth_log_signatures() {
    // The grep patterns MUST cover the standard pam_unix + sshd
    // + sudo signatures. Drift = missed events.
    for pattern in [
        "authentication failure",
        "Failed password",
        "session opened",
        "Accepted password",
        "Invalid user",
    ] {
        assert!(
            WRAPPER.contains(pattern),
            "wrapper must grep for canonical pattern {pattern:?}"
        );
    }
}

#[test]
fn wrapper_documents_honest_offline_contract() {
    assert!(
        WRAPPER.contains("Honest-offline") || WRAPPER.contains("honest-offline"),
        "wrapper docstring must document the honest-offline contract"
    );
}

#[test]
fn wrapper_supports_window_override() {
    assert!(
        WRAPPER.contains("SELFDEF_AUTH_EVENTS_WINDOW"),
        "wrapper must honor SELFDEF_AUTH_EVENTS_WINDOW env override"
    );
}

#[test]
fn wrapper_documents_brute_force_detection_purpose() {
    // The wrapper docstring MUST document why auth-event observation
    // is IPS-load-bearing.
    assert!(
        WRAPPER.contains("brute-force")
            || WRAPPER.contains("Brute-force")
            || WRAPPER.contains("brute force"),
        "wrapper docstring must explain brute-force detection purpose"
    );
}
