//! selfdef-cron-textfile observer — contract test.
//!
//! Locks the 15th sibling textfile observer shipped this commit.
//! Surfaces cron + systemd-timer persistence inventory. Pairs with
//! kernel-modules (12th sibling): kernel-modules catches in-kernel
//! rootkits; this catches userspace persistence vectors.

const SERVICE_UNIT: &str = include_str!("../../../packaging/systemd/selfdef-cron-textfile.service");
const TIMER_UNIT: &str = include_str!("../../../packaging/systemd/selfdef-cron-textfile.timer");
const WRAPPER: &str = include_str!("../../../packaging/scripts/selfdef-cron-textfile.sh");

#[test]
fn service_invokes_the_wrapper_at_canonical_path() {
    assert!(SERVICE_UNIT.contains("ExecStart=/usr/share/selfdef/selfdef-cron-textfile.sh"));
}

#[test]
fn service_writes_to_node_exporter_textfile_collector_dir() {
    assert!(SERVICE_UNIT.contains(
        "SELFDEF_CRON_TEXTFILE_PATH=/var/lib/node_exporter/textfile_collector/selfdef-cron.prom"
    ));
}

#[test]
fn service_runs_as_selfdef_user() {
    assert!(SERVICE_UNIT.contains("User=selfdef"));
    assert!(SERVICE_UNIT.contains("Group=selfdef"));
}

#[test]
fn service_reads_all_cron_surfaces_readonly() {
    for required in [
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/etc/crontab",
        "/var/spool/cron",
    ] {
        assert!(
            SERVICE_UNIT.contains(required),
            "service must grant ReadOnlyPaths to {required}"
        );
    }
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
fn timer_has_450s_offset_boot_delay() {
    // 15th sibling — 450s distinct above the 14 prior siblings.
    assert!(
        TIMER_UNIT.contains("OnBootSec=450s"),
        "timer must have 450s offset (15th distinct above 14 siblings)"
    );
}

#[test]
fn timer_binds_to_the_service() {
    assert!(TIMER_UNIT.contains("Unit=selfdef-cron-textfile.service"));
}

#[test]
fn wrapper_has_shebang_and_strict_mode() {
    assert!(WRAPPER.starts_with("#!/bin/bash"));
    assert!(WRAPPER.contains("set -euo pipefail"));
}

#[test]
fn wrapper_enumerates_etc_cron_d() {
    assert!(WRAPPER.contains("/etc/cron.d"));
}

#[test]
fn wrapper_enumerates_periodic_cron_dirs() {
    for sub in ["hourly", "daily", "weekly", "monthly"] {
        assert!(
            WRAPPER.contains(sub),
            "wrapper must enumerate /etc/cron.{sub}"
        );
    }
}

#[test]
fn wrapper_enumerates_user_crontabs() {
    assert!(WRAPPER.contains("/var/spool/cron"));
}

#[test]
fn wrapper_counts_systemd_timers() {
    assert!(WRAPPER.contains("systemctl list-timers"));
}

#[test]
fn wrapper_uses_atomic_tempfile_rename() {
    assert!(WRAPPER.contains("mktemp"));
    assert!(WRAPPER.contains("mv -f"));
}

#[test]
fn wrapper_emits_failure_sentinel() {
    assert!(WRAPPER.contains("selfdef_cron_textfile_emit_failed"));
}

#[test]
fn wrapper_emits_all_canonical_gauges() {
    for required in [
        "selfdef_cron_d_files",
        "selfdef_cron_periodic_files",
        "selfdef_cron_user_crontabs",
        "selfdef_cron_total_entries",
        "selfdef_systemd_timers_total",
        "selfdef_cron_last_run_unix",
        "selfdef_cron_textfile_emit_failed",
    ] {
        assert!(
            WRAPPER.contains(required),
            "wrapper must emit gauge {required}"
        );
    }
}

#[test]
fn wrapper_filters_comment_lines_from_entry_count() {
    // Total entry count must skip comments (^#) and blank lines.
    assert!(
        WRAPPER.contains("^[^#"),
        "wrapper must filter comment/blank lines from entry count"
    );
}

#[test]
fn wrapper_documents_pairing_with_kernel_modules() {
    assert!(
        WRAPPER.contains("kernel-modules") || WRAPPER.contains("rootkit"),
        "wrapper docstring should reference kernel-modules / rootkit pairing"
    );
}
