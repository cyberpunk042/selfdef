//! selfdef-revocations-textfile observer — contract test.
//!
//! Locks the 21st sibling textfile observer shipped this commit.
//! Surfaces the SDD-067 session-revocation state — completes
//! the enforcement-layer observability trio (blockset 19th +
//! quarantine 20th + revocations 21st).

const SERVICE_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-revocations-textfile.service");
const TIMER_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-revocations-textfile.timer");
const WRAPPER: &str = include_str!("../../../packaging/scripts/selfdef-revocations-textfile.sh");

#[test]
fn service_invokes_the_wrapper_at_canonical_path() {
    assert!(SERVICE_UNIT.contains("ExecStart=/usr/share/selfdef/selfdef-revocations-textfile.sh"));
}

#[test]
fn service_writes_to_node_exporter_textfile_collector_dir() {
    assert!(SERVICE_UNIT.contains(
        "SELFDEF_REVOCATIONS_TEXTFILE_PATH=/var/lib/node_exporter/textfile_collector/selfdef-revocations.prom"
    ));
}

#[test]
fn service_runs_as_selfdef_user() {
    assert!(SERVICE_UNIT.contains("User=selfdef"));
    assert!(SERVICE_UNIT.contains("Group=selfdef"));
}

#[test]
fn service_reads_revocations_state_dir() {
    assert!(SERVICE_UNIT.contains("SELFDEF_REVOCATIONS_STATE_DIR=/var/lib/selfdef/revocations"));
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
fn timer_has_630s_offset_boot_delay() {
    assert!(
        TIMER_UNIT.contains("OnBootSec=630s"),
        "timer must have 630s offset (21st distinct above 20 siblings)"
    );
}

#[test]
fn timer_binds_to_the_service() {
    assert!(TIMER_UNIT.contains("Unit=selfdef-revocations-textfile.service"));
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
    // Grep fallback for hosts without jq.
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
    assert!(WRAPPER.contains("selfdef_revocations_textfile_emit_failed"));
}

#[test]
fn wrapper_emits_all_canonical_gauges() {
    for required in [
        "selfdef_revocations_state_dir_present",
        "selfdef_revocations_active_count",
        "selfdef_revocations_pending_restores",
        "selfdef_revocations_oldest_expiry_unix",
        "selfdef_revocations_last_run_unix",
        "selfdef_revocations_textfile_emit_failed",
    ] {
        assert!(
            WRAPPER.contains(required),
            "wrapper must emit gauge {required}"
        );
    }
}

#[test]
fn wrapper_documents_sdd_067_anchor() {
    assert!(
        WRAPPER.contains("SDD-067"),
        "wrapper must cite SDD-067 anchor"
    );
}
