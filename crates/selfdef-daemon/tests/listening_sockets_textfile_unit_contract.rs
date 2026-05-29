//! selfdef-listening-sockets-textfile observer — contract test.
//!
//! Locks the 9th sibling textfile observer shipped this commit.
//! Surfaces per-protocol LISTEN socket counts so operators detect
//! unexpected listeners (post-exploitation backdoors, exposed dev
//! servers, baseline drift).

const SERVICE_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-listening-sockets-textfile.service");
const TIMER_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-listening-sockets-textfile.timer");
const WRAPPER: &str =
    include_str!("../../../packaging/scripts/selfdef-listening-sockets-textfile.sh");

// ──────────────────────────────────────────────── service unit tests

#[test]
fn service_invokes_the_wrapper_at_canonical_path() {
    assert!(
        SERVICE_UNIT.contains("ExecStart=/usr/share/selfdef/selfdef-listening-sockets-textfile.sh")
    );
}

#[test]
fn service_writes_to_node_exporter_textfile_collector_dir() {
    assert!(SERVICE_UNIT.contains(
        "SELFDEF_LISTENING_SOCKETS_TEXTFILE_PATH=/var/lib/node_exporter/textfile_collector/selfdef-listening-sockets.prom"
    ));
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
            "missing required hardening clause: {required}"
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
fn timer_has_270s_offset_boot_delay() {
    // 9th and latest observer timer — above the 8 sibling timers.
    assert!(
        TIMER_UNIT.contains("OnBootSec=270s"),
        "timer must have 270s offset (9th distinct above 8 siblings)"
    );
}

#[test]
fn timer_binds_to_the_service() {
    assert!(TIMER_UNIT.contains("Unit=selfdef-listening-sockets-textfile.service"));
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
fn wrapper_supports_ss_with_proc_fallback() {
    // Both code paths must be present: ss (preferred) + /proc/net
    // parsing (fallback when ss is absent on minimal hosts).
    assert!(WRAPPER.contains("command -v ss"));
    assert!(WRAPPER.contains("/proc/net/tcp"));
}

#[test]
fn wrapper_uses_atomic_tempfile_rename() {
    assert!(WRAPPER.contains("mktemp"));
    assert!(WRAPPER.contains("mv -f"));
}

#[test]
fn wrapper_emits_failure_sentinel_when_no_socket_inspection_available() {
    assert!(WRAPPER.contains("selfdef_listening_sockets_textfile_emit_failed"));
}

#[test]
fn wrapper_emits_all_canonical_gauges() {
    for required in [
        "selfdef_listening_sockets_tcp",
        "selfdef_listening_sockets_tcp6",
        "selfdef_listening_sockets_udp",
        "selfdef_listening_sockets_udp6",
        "selfdef_listening_sockets_total",
        "selfdef_listening_sockets_last_run_unix",
        "selfdef_listening_sockets_textfile_emit_failed",
    ] {
        assert!(
            WRAPPER.contains(required),
            "wrapper must emit gauge {required}"
        );
    }
}

#[test]
fn wrapper_ss_invocations_separate_ipv4_ipv6() {
    // Per-protocol counting requires separate ss -4 / ss -6 calls.
    assert!(WRAPPER.contains("ss -H -ltn4") || WRAPPER.contains("ss -ltn4"));
    assert!(WRAPPER.contains("ss -H -ltn6") || WRAPPER.contains("ss -ltn6"));
}

#[test]
fn wrapper_proc_fallback_parses_listen_state_0a() {
    // /proc/net/tcp uses state 0A for LISTEN.
    assert!(
        WRAPPER.contains("\"0A\"") || WRAPPER.contains("0A"),
        "proc fallback must filter on state 0A (LISTEN)"
    );
}

#[test]
fn wrapper_documents_honest_offline_contract() {
    assert!(WRAPPER.contains("Honest-offline") || WRAPPER.contains("honest-offline"),);
}

#[test]
fn wrapper_documents_backdoor_detection_purpose() {
    // Operator-actionable IPS-spine context.
    assert!(
        WRAPPER.contains("backdoor")
            || WRAPPER.contains("post-exploitation")
            || WRAPPER.contains("Post-exploitation"),
        "wrapper docstring must explain unexpected-listener detection purpose"
    );
}

#[test]
fn wrapper_total_count_sums_all_four_protocols() {
    // total_listeners must be the sum of all 4 protocol counts —
    // drift here = total drops below per-protocol sums.
    assert!(
        WRAPPER.contains("total_listeners=$(( tcp_count + tcp6_count + udp_count + udp6_count ))"),
        "wrapper must sum total across all 4 protocols"
    );
}
