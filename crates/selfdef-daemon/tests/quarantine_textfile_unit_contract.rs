//! selfdef-quarantine-textfile observer — contract test.
//!
//! Locks the 20th sibling textfile observer shipped this commit.
//! Surfaces the SDD-066 process-quarantine kernel-side state.
//! Pairs with blockset observer (19th sibling, SDD-065).

const SERVICE_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-quarantine-textfile.service");
const TIMER_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-quarantine-textfile.timer");
const WRAPPER: &str = include_str!("../../../packaging/scripts/selfdef-quarantine-textfile.sh");

#[test]
fn service_invokes_the_wrapper_at_canonical_path() {
    assert!(SERVICE_UNIT.contains("ExecStart=/usr/share/selfdef/selfdef-quarantine-textfile.sh"));
}

#[test]
fn service_writes_to_node_exporter_textfile_collector_dir() {
    assert!(SERVICE_UNIT.contains(
        "SELFDEF_QUARANTINE_TEXTFILE_PATH=/var/lib/node_exporter/textfile_collector/selfdef-quarantine.prom"
    ));
}

#[test]
fn service_runs_as_selfdef_user() {
    assert!(SERVICE_UNIT.contains("User=selfdef"));
    assert!(SERVICE_UNIT.contains("Group=selfdef"));
}

#[test]
fn service_grants_read_only_to_selfdef_slice() {
    assert!(SERVICE_UNIT.contains("/sys/fs/cgroup/selfdef.slice"));
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
fn timer_has_600s_offset_boot_delay() {
    assert!(
        TIMER_UNIT.contains("OnBootSec=600s"),
        "timer must have 600s offset (20th distinct above 19 siblings)"
    );
}

#[test]
fn timer_binds_to_the_service() {
    assert!(TIMER_UNIT.contains("Unit=selfdef-quarantine-textfile.service"));
}

#[test]
fn wrapper_has_shebang_and_strict_mode() {
    assert!(WRAPPER.starts_with("#!/bin/bash"));
    assert!(WRAPPER.contains("set -euo pipefail"));
}

#[test]
fn wrapper_iterates_quarantine_scope_entries() {
    assert!(
        WRAPPER.contains("quarantine-*.scope"),
        "wrapper must iterate quarantine-*.scope entries under selfdef.slice"
    );
}

#[test]
fn wrapper_reads_cgroup_freeze_for_freeze_state() {
    assert!(
        WRAPPER.contains("cgroup.freeze"),
        "wrapper must read cgroup.freeze for per-scope freeze state"
    );
}

#[test]
fn wrapper_parses_systemd_list_timers_for_expiry() {
    assert!(
        WRAPPER.contains("systemctl list-timers"),
        "wrapper must parse systemctl list-timers for SDD-066 §3a auto-release timer entries"
    );
}

#[test]
fn wrapper_uses_atomic_tempfile_rename() {
    assert!(WRAPPER.contains("mktemp"));
    assert!(WRAPPER.contains("mv -f"));
}

#[test]
fn wrapper_emits_failure_sentinel() {
    assert!(WRAPPER.contains("selfdef_quarantine_textfile_emit_failed"));
}

#[test]
fn wrapper_handles_missing_slice_honest_offline() {
    // Honest-offline when /sys/fs/cgroup/selfdef.slice doesn't exist.
    assert!(WRAPPER.contains("if [ -d \"$SLICE_PATH\" ]; then"));
}

#[test]
fn wrapper_emits_all_canonical_gauges() {
    for required in [
        "selfdef_quarantine_slice_present",
        "selfdef_quarantine_active_count",
        "selfdef_quarantine_frozen_count",
        "selfdef_quarantine_oldest_expiry_unix",
        "selfdef_quarantine_last_run_unix",
        "selfdef_quarantine_textfile_emit_failed",
    ] {
        assert!(
            WRAPPER.contains(required),
            "wrapper must emit gauge {required}"
        );
    }
}

#[test]
fn wrapper_documents_sdd_066_anchor() {
    assert!(
        WRAPPER.contains("SDD-066"),
        "wrapper must cite SDD-066 anchor"
    );
}
