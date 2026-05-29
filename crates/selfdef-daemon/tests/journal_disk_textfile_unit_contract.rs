//! selfdef-journal-disk-textfile observer — contract test.
//!
//! Locks the 18th sibling textfile observer shipped this commit.
//! Surfaces systemd-journal disk usage. Pairs with disk-usage
//! (8th sibling) at the operational-disk axis.

const SERVICE_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-journal-disk-textfile.service");
const TIMER_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-journal-disk-textfile.timer");
const WRAPPER: &str = include_str!("../../../packaging/scripts/selfdef-journal-disk-textfile.sh");

#[test]
fn service_invokes_the_wrapper_at_canonical_path() {
    assert!(SERVICE_UNIT.contains("ExecStart=/usr/share/selfdef/selfdef-journal-disk-textfile.sh"));
}

#[test]
fn service_writes_to_node_exporter_textfile_collector_dir() {
    assert!(SERVICE_UNIT.contains(
        "SELFDEF_JOURNAL_DISK_TEXTFILE_PATH=/var/lib/node_exporter/textfile_collector/selfdef-journal-disk.prom"
    ));
}

#[test]
fn service_runs_as_selfdef_user() {
    assert!(SERVICE_UNIT.contains("User=selfdef"));
    assert!(SERVICE_UNIT.contains("Group=selfdef"));
}

#[test]
fn service_reads_journal_dirs_readonly() {
    for required in ["/var/log/journal", "/run/log/journal"] {
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
fn timer_has_540s_offset_boot_delay() {
    // 18th sibling — 540s distinct above the 17 prior siblings.
    assert!(
        TIMER_UNIT.contains("OnBootSec=540s"),
        "timer must have 540s offset (18th distinct above 17 siblings)"
    );
}

#[test]
fn timer_binds_to_the_service() {
    assert!(TIMER_UNIT.contains("Unit=selfdef-journal-disk-textfile.service"));
}

#[test]
fn wrapper_has_shebang_and_strict_mode() {
    assert!(WRAPPER.starts_with("#!/bin/bash"));
    assert!(WRAPPER.contains("set -euo pipefail"));
}

#[test]
fn wrapper_calls_journalctl_disk_usage() {
    assert!(
        WRAPPER.contains("journalctl --disk-usage"),
        "wrapper must call journalctl --disk-usage"
    );
}

#[test]
fn wrapper_handles_missing_journalctl() {
    assert!(
        WRAPPER.contains("command -v journalctl"),
        "wrapper must honest-offline if journalctl missing"
    );
}

#[test]
fn wrapper_detects_persistent_journal_via_var_log_journal() {
    assert!(
        WRAPPER.contains("/var/log/journal"),
        "wrapper must detect persistent journal via /var/log/journal/"
    );
}

#[test]
fn wrapper_detects_volatile_journal_via_run_log_journal() {
    assert!(
        WRAPPER.contains("/run/log/journal"),
        "wrapper must detect volatile journal via /run/log/journal/"
    );
}

#[test]
fn wrapper_handles_all_size_suffixes() {
    // K/M/G/T conversion to bytes.
    for suffix in ["K", "M", "G", "T"] {
        assert!(
            WRAPPER.contains(&format!("{suffix})")),
            "wrapper must convert {suffix} suffix to bytes"
        );
    }
}

#[test]
fn wrapper_uses_atomic_tempfile_rename() {
    assert!(WRAPPER.contains("mktemp"));
    assert!(WRAPPER.contains("mv -f"));
}

#[test]
fn wrapper_emits_failure_sentinel() {
    assert!(WRAPPER.contains("selfdef_journal_disk_textfile_emit_failed"));
}

#[test]
fn wrapper_emits_all_canonical_gauges() {
    for required in [
        "selfdef_journal_available",
        "selfdef_journal_bytes_total",
        "selfdef_journal_persistent",
        "selfdef_journal_volatile",
        "selfdef_journal_disk_last_run_unix",
        "selfdef_journal_disk_textfile_emit_failed",
    ] {
        assert!(
            WRAPPER.contains(required),
            "wrapper must emit gauge {required}"
        );
    }
}

#[test]
fn wrapper_documents_pairing_with_disk_usage() {
    assert!(
        WRAPPER.contains("disk-usage") || WRAPPER.contains("disk_usage"),
        "wrapper docstring should reference disk-usage pairing"
    );
}
