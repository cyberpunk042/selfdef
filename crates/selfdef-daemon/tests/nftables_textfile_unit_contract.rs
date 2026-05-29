//! selfdef-nftables-textfile observer — contract test.
//!
//! Locks the 14th sibling textfile observer shipped this commit.
//! Surfaces nftables ruleset state + conntrack fill-rate. Pairs
//! with fail2ban (13th sibling): fail2ban acts in-process;
//! nftables is the actual kernel packet-filter.

const SERVICE_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-nftables-textfile.service");
const TIMER_UNIT: &str = include_str!("../../../packaging/systemd/selfdef-nftables-textfile.timer");
const WRAPPER: &str = include_str!("../../../packaging/scripts/selfdef-nftables-textfile.sh");

#[test]
fn service_invokes_the_wrapper_at_canonical_path() {
    assert!(SERVICE_UNIT.contains("ExecStart=/usr/share/selfdef/selfdef-nftables-textfile.sh"));
}

#[test]
fn service_writes_to_node_exporter_textfile_collector_dir() {
    assert!(SERVICE_UNIT.contains(
        "SELFDEF_NFTABLES_TEXTFILE_PATH=/var/lib/node_exporter/textfile_collector/selfdef-nftables.prom"
    ));
}

#[test]
fn service_runs_as_selfdef_user() {
    assert!(SERVICE_UNIT.contains("User=selfdef"));
    assert!(SERVICE_UNIT.contains("Group=selfdef"));
}

#[test]
fn service_grants_cap_net_admin_only() {
    // Documented exception: nft list ruleset requires CAP_NET_ADMIN.
    assert!(SERVICE_UNIT.contains("AmbientCapabilities=CAP_NET_ADMIN"));
    assert!(SERVICE_UNIT.contains("CapabilityBoundingSet=CAP_NET_ADMIN"));
}

#[test]
fn service_allows_netlink_for_nft_to_kernel() {
    // nft uses NETLINK_NETFILTER; must be in RestrictAddressFamilies.
    assert!(SERVICE_UNIT.contains("RestrictAddressFamilies=AF_UNIX AF_NETLINK"));
}

#[test]
fn service_documents_private_network_false_exception() {
    // Sibling observers use PrivateNetwork=true; this one needs the
    // host netns for netlink kernel-rpc.
    assert!(SERVICE_UNIT.contains("PrivateNetwork=false"));
}

#[test]
fn service_grants_write_only_to_textfile_collector() {
    assert!(SERVICE_UNIT.contains("ReadWritePaths=/var/lib/node_exporter/textfile_collector"));
    assert!(!SERVICE_UNIT.contains("ReadWritePaths=/var/lib/selfdef"));
}

#[test]
fn service_keeps_majority_of_r171_hardening() {
    // 10 of the 12 R171 clauses still apply (the 2 exceptions are
    // PrivateNetwork + RestrictAddressFamilies-extension above).
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
fn timer_has_420s_offset_boot_delay() {
    // 14th sibling — 420s distinct above the 13 prior siblings.
    assert!(
        TIMER_UNIT.contains("OnBootSec=420s"),
        "timer must have 420s offset (14th distinct above 13 siblings)"
    );
}

#[test]
fn timer_binds_to_the_service() {
    assert!(TIMER_UNIT.contains("Unit=selfdef-nftables-textfile.service"));
}

#[test]
fn wrapper_has_shebang_and_strict_mode() {
    assert!(WRAPPER.starts_with("#!/bin/bash"));
    assert!(WRAPPER.contains("set -euo pipefail"));
}

#[test]
fn wrapper_reads_conntrack_count_and_max() {
    assert!(WRAPPER.contains("/proc/sys/net/netfilter/nf_conntrack_count"));
    assert!(WRAPPER.contains("/proc/sys/net/netfilter/nf_conntrack_max"));
}

#[test]
fn wrapper_handles_missing_nft_command() {
    // Honest-offline: nft is optional (conntrack metrics still emit).
    assert!(
        WRAPPER.contains("command -v nft"),
        "wrapper must check for nft presence (honest-offline)"
    );
}

#[test]
fn wrapper_uses_atomic_tempfile_rename() {
    assert!(WRAPPER.contains("mktemp"));
    assert!(WRAPPER.contains("mv -f"));
}

#[test]
fn wrapper_emits_failure_sentinel() {
    assert!(WRAPPER.contains("selfdef_nftables_textfile_emit_failed"));
}

#[test]
fn wrapper_emits_all_canonical_gauges() {
    for required in [
        "selfdef_nftables_present",
        "selfdef_nftables_tables_total",
        "selfdef_nftables_chains_total",
        "selfdef_nftables_rules_total",
        "selfdef_conntrack_count",
        "selfdef_conntrack_max",
        "selfdef_conntrack_used_percent",
        "selfdef_nftables_last_run_unix",
        "selfdef_nftables_textfile_emit_failed",
    ] {
        assert!(
            WRAPPER.contains(required),
            "wrapper must emit gauge {required}"
        );
    }
}

#[test]
fn wrapper_computes_conntrack_used_percent() {
    // Integer arithmetic: (count * 100) / max.
    assert!(
        WRAPPER.contains("conntrack_count * 100") || WRAPPER.contains("count * 100"),
        "wrapper must compute conntrack_used_percent"
    );
}

#[test]
fn wrapper_parses_nft_handle_count_for_rules() {
    // nft -a tags each rule with "# handle N".
    assert!(
        WRAPPER.contains("handle "),
        "wrapper must count rules by parsing # handle N markers"
    );
}

#[test]
fn wrapper_documents_pairing_with_fail2ban() {
    assert!(
        WRAPPER.contains("fail2ban"),
        "wrapper docstring should reference fail2ban pairing"
    );
}
