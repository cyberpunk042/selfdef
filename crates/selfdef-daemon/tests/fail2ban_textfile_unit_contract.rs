//! selfdef-fail2ban-textfile observer — contract test.
//!
//! Locks the 13th sibling textfile observer shipped this commit.
//! Surfaces fail2ban-server alive-state, active-jail count, and
//! per-jail current/total ban counters. Pairs with auth-events
//! (11th sibling) — together: complete attack-detected /
//! attack-mitigated IPS observability pair.

const SERVICE_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-fail2ban-textfile.service");
const TIMER_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-fail2ban-textfile.timer");
const WRAPPER: &str = include_str!("../../../packaging/scripts/selfdef-fail2ban-textfile.sh");

#[test]
fn service_invokes_the_wrapper_at_canonical_path() {
    assert!(
        SERVICE_UNIT.contains("ExecStart=/usr/share/selfdef/selfdef-fail2ban-textfile.sh")
    );
}

#[test]
fn service_writes_to_node_exporter_textfile_collector_dir() {
    assert!(SERVICE_UNIT.contains(
        "SELFDEF_FAIL2BAN_TEXTFILE_PATH=/var/lib/node_exporter/textfile_collector/selfdef-fail2ban.prom"
    ));
}

#[test]
fn service_runs_as_selfdef_user() {
    assert!(SERVICE_UNIT.contains("User=selfdef"));
    assert!(SERVICE_UNIT.contains("Group=selfdef"));
}

#[test]
fn service_grants_write_only_to_textfile_collector() {
    assert!(SERVICE_UNIT.contains("ReadWritePaths=/var/lib/node_exporter/textfile_collector"));
    assert!(!SERVICE_UNIT.contains("ReadWritePaths=/var/lib/selfdef"));
}

#[test]
fn service_grants_read_only_to_fail2ban_runtime_socket() {
    // fail2ban-client must reach /var/run/fail2ban/fail2ban.sock.
    assert!(
        SERVICE_UNIT.contains("/var/run/fail2ban"),
        "service must allow read of /var/run/fail2ban for client socket"
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
            "missing hardening clause: {required}"
        );
    }
}

#[test]
fn service_treats_success_as_success_only() {
    assert!(SERVICE_UNIT.contains("SuccessExitStatus=0"));
}

#[test]
fn timer_runs_every_60_seconds() {
    assert!(TIMER_UNIT.contains("OnUnitActiveSec=60s"));
}

#[test]
fn timer_has_390s_offset_boot_delay() {
    // 13th sibling — 390s distinct above the 12 prior siblings.
    assert!(
        TIMER_UNIT.contains("OnBootSec=390s"),
        "timer must have 390s offset (13th distinct above 12 siblings)"
    );
}

#[test]
fn timer_binds_to_the_service() {
    assert!(TIMER_UNIT.contains("Unit=selfdef-fail2ban-textfile.service"));
}

#[test]
fn timer_install_section_wantedby_timers_target() {
    assert!(TIMER_UNIT.contains("[Install]"));
    assert!(TIMER_UNIT.contains("WantedBy=timers.target"));
}

#[test]
fn wrapper_has_shebang_and_strict_mode() {
    assert!(WRAPPER.starts_with("#!/bin/bash"));
    assert!(WRAPPER.contains("set -euo pipefail"));
}

#[test]
fn wrapper_pings_fail2ban_server() {
    assert!(
        WRAPPER.contains("fail2ban-client ping"),
        "wrapper must ping fail2ban-server for alive-state"
    );
}

#[test]
fn wrapper_handles_missing_fail2ban_client() {
    // Honest-offline when fail2ban-client absent.
    assert!(
        WRAPPER.contains("command -v fail2ban-client"),
        "wrapper must check for fail2ban-client presence"
    );
}

#[test]
fn wrapper_emits_minus_one_when_client_missing() {
    // -1 sentinel distinguishes "client missing" from "daemon down".
    assert!(
        WRAPPER.contains("selfdef_fail2ban_server_alive -1"),
        "wrapper must emit -1 sentinel when fail2ban-client uninstalled"
    );
}

#[test]
fn wrapper_uses_atomic_tempfile_rename() {
    assert!(WRAPPER.contains("mktemp"));
    assert!(WRAPPER.contains("mv -f"));
}

#[test]
fn wrapper_emits_failure_sentinel() {
    assert!(WRAPPER.contains("selfdef_fail2ban_textfile_emit_failed"));
}

#[test]
fn wrapper_emits_all_canonical_gauges() {
    for required in [
        "selfdef_fail2ban_server_alive",
        "selfdef_fail2ban_jails_active",
        "selfdef_fail2ban_jail_current_bans",
        "selfdef_fail2ban_jail_total_bans",
        "selfdef_fail2ban_current_bans_sum",
        "selfdef_fail2ban_total_bans_sum",
        "selfdef_fail2ban_last_run_unix",
        "selfdef_fail2ban_textfile_emit_failed",
    ] {
        assert!(
            WRAPPER.contains(required),
            "wrapper must emit gauge {required}"
        );
    }
}

#[test]
fn wrapper_iterates_jails_with_per_jail_status_calls() {
    assert!(
        WRAPPER.contains("fail2ban-client status"),
        "wrapper must call fail2ban-client status (per-jail iteration)"
    );
}

#[test]
fn wrapper_documents_pairing_with_auth_events() {
    // The 11th-sibling auth-events observer detects attack attempts;
    // this (13th sibling) measures the defensive response.
    assert!(
        WRAPPER.contains("auth-events") || WRAPPER.contains("auth_events"),
        "wrapper docstring should reference auth-events pairing"
    );
}
