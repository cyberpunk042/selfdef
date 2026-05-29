//! selfdef-blockset-textfile observer — contract test.
//!
//! Locks the 19th sibling textfile observer shipped this commit.
//! Surfaces the SDD-065 kernel-side selfdef-blocks nft table
//! state. Pairs with nftables observer (14th sibling) at the
//! kernel-packet-filter axis.

const SERVICE_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-blockset-textfile.service");
const TIMER_UNIT: &str = include_str!("../../../packaging/systemd/selfdef-blockset-textfile.timer");
const WRAPPER: &str = include_str!("../../../packaging/scripts/selfdef-blockset-textfile.sh");

#[test]
fn service_invokes_the_wrapper_at_canonical_path() {
    assert!(SERVICE_UNIT.contains("ExecStart=/usr/share/selfdef/selfdef-blockset-textfile.sh"));
}

#[test]
fn service_writes_to_node_exporter_textfile_collector_dir() {
    assert!(SERVICE_UNIT.contains(
        "SELFDEF_BLOCKSET_TEXTFILE_PATH=/var/lib/node_exporter/textfile_collector/selfdef-blockset.prom"
    ));
}

#[test]
fn service_runs_as_selfdef_user() {
    assert!(SERVICE_UNIT.contains("User=selfdef"));
    assert!(SERVICE_UNIT.contains("Group=selfdef"));
}

#[test]
fn service_grants_cap_net_admin_only() {
    // Documented exception per SDD-065: nft list set requires
    // CAP_NET_ADMIN. CapabilityBoundingSet bounds to the same
    // single cap.
    assert!(SERVICE_UNIT.contains("AmbientCapabilities=CAP_NET_ADMIN"));
    assert!(SERVICE_UNIT.contains("CapabilityBoundingSet=CAP_NET_ADMIN"));
}

#[test]
fn service_keeps_majority_of_r171_hardening() {
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
fn timer_has_570s_offset_boot_delay() {
    assert!(
        TIMER_UNIT.contains("OnBootSec=570s"),
        "timer must have 570s offset (19th distinct above 18 siblings)"
    );
}

#[test]
fn timer_binds_to_the_service() {
    assert!(TIMER_UNIT.contains("Unit=selfdef-blockset-textfile.service"));
}

#[test]
fn wrapper_has_shebang_and_strict_mode() {
    assert!(WRAPPER.starts_with("#!/bin/bash"));
    assert!(WRAPPER.contains("set -euo pipefail"));
}

#[test]
fn wrapper_invokes_nft_list_set_for_both_families() {
    assert!(WRAPPER.contains("nft list set inet selfdef-blocks v4"));
    assert!(WRAPPER.contains("nft list set inet selfdef-blocks v6"));
}

#[test]
fn wrapper_detects_table_presence_via_list_table() {
    assert!(WRAPPER.contains("nft -a list table inet selfdef-blocks"));
}

#[test]
fn wrapper_parses_expires_token_for_oldest_ttl() {
    // SDD-065 §3 — flags-timeout → kernel emits "expires Ns".
    assert!(WRAPPER.contains("expires"));
}

#[test]
fn wrapper_uses_atomic_tempfile_rename() {
    assert!(WRAPPER.contains("mktemp"));
    assert!(WRAPPER.contains("mv -f"));
}

#[test]
fn wrapper_emits_failure_sentinel() {
    assert!(WRAPPER.contains("selfdef_blockset_textfile_emit_failed"));
}

#[test]
fn wrapper_handles_missing_nft_command_honest_offline() {
    assert!(WRAPPER.contains("command -v nft"));
}

#[test]
fn wrapper_emits_all_canonical_gauges() {
    for required in [
        "selfdef_blockset_present",
        "selfdef_blockset_v4_count",
        "selfdef_blockset_v6_count",
        "selfdef_blockset_total_count",
        "selfdef_blockset_oldest_expiry_unix",
        "selfdef_blockset_last_run_unix",
        "selfdef_blockset_textfile_emit_failed",
    ] {
        assert!(
            WRAPPER.contains(required),
            "wrapper must emit gauge {required}"
        );
    }
}

#[test]
fn wrapper_documents_sdd_065_anchor() {
    assert!(
        WRAPPER.contains("SDD-065"),
        "wrapper must cite SDD-065 anchor"
    );
}
