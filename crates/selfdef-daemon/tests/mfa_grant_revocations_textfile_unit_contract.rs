//! selfdef-mfa-grant-revocations-textfile observer — contract test.
//! 23rd sibling completes the IPS-pentet observability set.

const SERVICE_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-mfa-grant-revocations-textfile.service");
const TIMER_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-mfa-grant-revocations-textfile.timer");
const WRAPPER: &str =
    include_str!("../../../packaging/scripts/selfdef-mfa-grant-revocations-textfile.sh");

#[test]
fn service_invokes_wrapper_at_canonical_path() {
    assert!(
        SERVICE_UNIT
            .contains("ExecStart=/usr/share/selfdef/selfdef-mfa-grant-revocations-textfile.sh")
    );
}

#[test]
fn service_writes_to_textfile_collector_dir() {
    assert!(SERVICE_UNIT.contains("SELFDEF_MFA_GRANT_REVOCATIONS_TEXTFILE_PATH=/var/lib/node_exporter/textfile_collector/selfdef-mfa-grant-revocations.prom"));
}

#[test]
fn service_reads_state_dir() {
    assert!(SERVICE_UNIT.contains(
        "SELFDEF_MFA_GRANT_REVOCATIONS_STATE_DIR=/var/lib/selfdef/mfa-grant-revocations"
    ));
}

#[test]
fn service_runs_as_selfdef_user() {
    assert!(SERVICE_UNIT.contains("User=selfdef"));
    assert!(SERVICE_UNIT.contains("Group=selfdef"));
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
        assert!(SERVICE_UNIT.contains(required), "missing: {required}");
    }
}

#[test]
fn timer_runs_every_60_seconds() {
    assert!(TIMER_UNIT.contains("OnUnitActiveSec=60s"));
}

#[test]
fn timer_has_690s_offset_boot_delay() {
    assert!(
        TIMER_UNIT.contains("OnBootSec=690s"),
        "timer must have 690s offset (23rd sibling)"
    );
}

#[test]
fn timer_binds_to_the_service() {
    assert!(TIMER_UNIT.contains("Unit=selfdef-mfa-grant-revocations-textfile.service"));
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
fn wrapper_uses_jq_with_grep_fallback() {
    assert!(WRAPPER.contains("command -v jq"));
    assert!(WRAPPER.contains("grep -oE"));
}

#[test]
fn wrapper_handles_missing_state_dir() {
    assert!(WRAPPER.contains("if [ -d \"$STATE_DIR\" ]; then"));
}

#[test]
fn wrapper_uses_atomic_tempfile_rename() {
    assert!(WRAPPER.contains("mktemp"));
    assert!(WRAPPER.contains("mv -f"));
}

#[test]
fn wrapper_emits_failure_sentinel() {
    assert!(WRAPPER.contains("selfdef_mfa_grant_revocations_textfile_emit_failed"));
}

#[test]
fn wrapper_emits_all_canonical_gauges() {
    for required in [
        "selfdef_mfa_grant_revocations_state_dir_present",
        "selfdef_mfa_grant_revocations_active_count",
        "selfdef_mfa_grant_revocations_pending_restores",
        "selfdef_mfa_grant_revocations_oldest_expiry_unix",
        "selfdef_mfa_grant_revocations_last_run_unix",
        "selfdef_mfa_grant_revocations_textfile_emit_failed",
    ] {
        assert!(WRAPPER.contains(required), "wrapper must emit: {required}");
    }
}

#[test]
fn wrapper_documents_sdd_069_anchor() {
    assert!(WRAPPER.contains("SDD-069"));
}
