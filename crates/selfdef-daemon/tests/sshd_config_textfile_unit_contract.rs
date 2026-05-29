//! selfdef-sshd-config-textfile observer — contract test.
//!
//! Locks the 16th sibling textfile observer shipped this commit.
//! Surfaces SSH server hardening baseline (content hash + 7 safety
//! toggles). Pairs with auth-events (11th sibling) at the
//! attack-surface axis.

const SERVICE_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-sshd-config-textfile.service");
const TIMER_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-sshd-config-textfile.timer");
const WRAPPER: &str = include_str!("../../../packaging/scripts/selfdef-sshd-config-textfile.sh");

#[test]
fn service_invokes_the_wrapper_at_canonical_path() {
    assert!(SERVICE_UNIT.contains("ExecStart=/usr/share/selfdef/selfdef-sshd-config-textfile.sh"));
}

#[test]
fn service_writes_to_node_exporter_textfile_collector_dir() {
    assert!(SERVICE_UNIT.contains(
        "SELFDEF_SSHD_CONFIG_TEXTFILE_PATH=/var/lib/node_exporter/textfile_collector/selfdef-sshd-config.prom"
    ));
}

#[test]
fn service_runs_as_selfdef_user() {
    assert!(SERVICE_UNIT.contains("User=selfdef"));
    assert!(SERVICE_UNIT.contains("Group=selfdef"));
}

#[test]
fn service_grants_read_only_to_etc_ssh() {
    assert!(SERVICE_UNIT.contains("/etc/ssh"));
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
            "missing hardening clause: {required}"
        );
    }
}

#[test]
fn timer_runs_every_60_seconds() {
    assert!(TIMER_UNIT.contains("OnUnitActiveSec=60s"));
}

#[test]
fn timer_has_480s_offset_boot_delay() {
    // 16th sibling — 480s distinct above the 15 prior siblings.
    assert!(
        TIMER_UNIT.contains("OnBootSec=480s"),
        "timer must have 480s offset (16th distinct above 15 siblings)"
    );
}

#[test]
fn timer_binds_to_the_service() {
    assert!(TIMER_UNIT.contains("Unit=selfdef-sshd-config-textfile.service"));
}

#[test]
fn wrapper_has_shebang_and_strict_mode() {
    assert!(WRAPPER.starts_with("#!/bin/bash"));
    assert!(WRAPPER.contains("set -euo pipefail"));
}

#[test]
fn wrapper_reads_sshd_config_default_path() {
    assert!(WRAPPER.contains("/etc/ssh/sshd_config"));
}

#[test]
fn wrapper_computes_sha256_content_hash() {
    assert!(
        WRAPPER.contains("sha256sum"),
        "wrapper must compute SHA-256 hash for drift detection"
    );
}

#[test]
fn wrapper_parses_all_7_safety_toggles() {
    for toggle in [
        "PermitRootLogin",
        "PasswordAuthentication",
        "PermitEmptyPasswords",
        "ChallengeResponseAuthentication",
        "X11Forwarding",
        "UsePAM",
        "Protocol",
    ] {
        assert!(
            WRAPPER.contains(toggle),
            "wrapper must parse sshd_config toggle {toggle}"
        );
    }
}

#[test]
fn wrapper_use_pam_default_is_safe_one() {
    // UsePAM defaults to 1 (safe) — only flipped to 0 if explicitly disabled.
    assert!(
        WRAPPER.contains("use_pam=1"),
        "use_pam default must be 1 (safe)"
    );
}

#[test]
fn wrapper_protocol_v2_only_default_is_safe_one() {
    assert!(
        WRAPPER.contains("protocol_v2_only=1"),
        "protocol_v2_only default must be 1 (safe)"
    );
}

#[test]
fn wrapper_uses_atomic_tempfile_rename() {
    assert!(WRAPPER.contains("mktemp"));
    assert!(WRAPPER.contains("mv -f"));
}

#[test]
fn wrapper_emits_failure_sentinel() {
    assert!(WRAPPER.contains("selfdef_sshd_config_textfile_emit_failed"));
}

#[test]
fn wrapper_emits_all_canonical_gauges() {
    for required in [
        "selfdef_sshd_config_present",
        "selfdef_sshd_config_hash",
        "selfdef_sshd_permit_root_login",
        "selfdef_sshd_password_authentication",
        "selfdef_sshd_permit_empty_passwords",
        "selfdef_sshd_challenge_response",
        "selfdef_sshd_x11_forwarding",
        "selfdef_sshd_use_pam",
        "selfdef_sshd_protocol_v2_only",
        "selfdef_sshd_config_last_run_unix",
        "selfdef_sshd_config_textfile_emit_failed",
    ] {
        assert!(
            WRAPPER.contains(required),
            "wrapper must emit gauge {required}"
        );
    }
}

#[test]
fn wrapper_documents_pairing_with_auth_events() {
    assert!(
        WRAPPER.contains("auth-events") || WRAPPER.contains("auth_events"),
        "wrapper docstring should reference auth-events pairing"
    );
}
