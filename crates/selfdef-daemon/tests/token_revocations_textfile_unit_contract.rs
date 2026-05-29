//! selfdef-token-revocations-textfile observer — contract test.
//!
//! 22nd sibling. Completes the IPS-quartet observability set:
//! 19th blockset + 20th quarantine + 21st revocations + 22nd
//! token-revocations.

const SERVICE_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-token-revocations-textfile.service");
const TIMER_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-token-revocations-textfile.timer");
const WRAPPER: &str =
    include_str!("../../../packaging/scripts/selfdef-token-revocations-textfile.sh");

#[test]
fn service_invokes_the_wrapper_at_canonical_path() {
    assert!(
        SERVICE_UNIT.contains("ExecStart=/usr/share/selfdef/selfdef-token-revocations-textfile.sh")
    );
}

#[test]
fn service_writes_to_node_exporter_textfile_collector_dir() {
    assert!(SERVICE_UNIT.contains(
        "SELFDEF_TOKEN_REVOCATIONS_TEXTFILE_PATH=/var/lib/node_exporter/textfile_collector/selfdef-token-revocations.prom"
    ));
}

#[test]
fn service_runs_as_selfdef_user() {
    assert!(SERVICE_UNIT.contains("User=selfdef"));
    assert!(SERVICE_UNIT.contains("Group=selfdef"));
}

#[test]
fn service_reads_token_revocations_state_dir() {
    assert!(
        SERVICE_UNIT
            .contains("SELFDEF_TOKEN_REVOCATIONS_STATE_DIR=/var/lib/selfdef/token-revocations")
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
fn timer_runs_every_60_seconds() {
    assert!(TIMER_UNIT.contains("OnUnitActiveSec=60s"));
}

#[test]
fn timer_has_660s_offset_boot_delay() {
    assert!(
        TIMER_UNIT.contains("OnBootSec=660s"),
        "timer must have 660s offset (22nd distinct above 21 siblings)"
    );
}

#[test]
fn timer_binds_to_the_service() {
    assert!(TIMER_UNIT.contains("Unit=selfdef-token-revocations-textfile.service"));
}

#[test]
fn wrapper_has_shebang_and_strict_mode() {
    assert!(WRAPPER.starts_with("#!/bin/bash"));
    assert!(WRAPPER.contains("set -euo pipefail"));
}

#[test]
fn wrapper_reads_active_and_pending_json_files() {
    assert!(WRAPPER.contains("active.json"));
    assert!(WRAPPER.contains("pending-restores.json"));
}

#[test]
fn wrapper_uses_jq_when_available_with_grep_fallback() {
    assert!(WRAPPER.contains("command -v jq"));
    assert!(WRAPPER.contains("grep -oE"));
}

#[test]
fn wrapper_handles_missing_state_dir_honest_offline() {
    assert!(WRAPPER.contains("if [ -d \"$STATE_DIR\" ]; then"));
}

#[test]
fn wrapper_uses_atomic_tempfile_rename() {
    assert!(WRAPPER.contains("mktemp"));
    assert!(WRAPPER.contains("mv -f"));
}

#[test]
fn wrapper_emits_failure_sentinel() {
    assert!(WRAPPER.contains("selfdef_token_revocations_textfile_emit_failed"));
}

#[test]
fn wrapper_emits_all_canonical_gauges() {
    for required in [
        "selfdef_token_revocations_state_dir_present",
        "selfdef_token_revocations_active_count",
        "selfdef_token_revocations_pending_restores",
        "selfdef_token_revocations_oldest_expiry_unix",
        "selfdef_token_revocations_last_run_unix",
        "selfdef_token_revocations_textfile_emit_failed",
    ] {
        assert!(
            WRAPPER.contains(required),
            "wrapper must emit gauge {required}"
        );
    }
}

#[test]
fn wrapper_documents_sdd_068_anchor() {
    assert!(
        WRAPPER.contains("SDD-068"),
        "wrapper must cite SDD-068 anchor"
    );
}
