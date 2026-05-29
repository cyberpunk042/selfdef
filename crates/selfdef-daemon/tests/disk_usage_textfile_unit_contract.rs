//! selfdef-disk-usage-textfile observer — contract test.
//!
//! Locks the 10th sibling textfile observer shipped this commit.
//! Surfaces per-directory disk usage so operators detect disk-fill
//! attacks before they wedge the IPS spine.

const SERVICE_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-disk-usage-textfile.service");
const TIMER_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-disk-usage-textfile.timer");
const WRAPPER: &str = include_str!("../../../packaging/scripts/selfdef-disk-usage-textfile.sh");

#[test]
fn service_invokes_the_wrapper_at_canonical_path() {
    assert!(SERVICE_UNIT.contains("ExecStart=/usr/share/selfdef/selfdef-disk-usage-textfile.sh"));
}

#[test]
fn service_writes_to_node_exporter_textfile_collector_dir() {
    assert!(SERVICE_UNIT.contains(
        "SELFDEF_DISK_USAGE_TEXTFILE_PATH=/var/lib/node_exporter/textfile_collector/selfdef-disk-usage.prom"
    ));
}

#[test]
fn service_runs_as_selfdef_user() {
    assert!(SERVICE_UNIT.contains("User=selfdef"));
    assert!(SERVICE_UNIT.contains("Group=selfdef"));
}

#[test]
fn service_grants_read_to_var_log_for_du() {
    // du needs read access to /var/log too — distinct from the
    // sibling observers that only read /var/lib/selfdef.
    assert!(
        SERVICE_UNIT.contains("ReadOnlyPaths=") && SERVICE_UNIT.contains("/var/log"),
        "service must grant read access to /var/log for du"
    );
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
fn service_treats_success_as_success_only() {
    assert!(SERVICE_UNIT.contains("SuccessExitStatus=0"));
}

#[test]
fn timer_runs_every_60_seconds() {
    assert!(TIMER_UNIT.contains("OnUnitActiveSec=60s"));
}

#[test]
fn timer_has_300s_offset_boot_delay() {
    // 10th sibling timer — above the 9 previous timers.
    assert!(
        TIMER_UNIT.contains("OnBootSec=300s"),
        "timer must have 300s offset (10th distinct above 9 siblings)"
    );
}

#[test]
fn timer_binds_to_the_service() {
    assert!(TIMER_UNIT.contains("Unit=selfdef-disk-usage-textfile.service"));
}

#[test]
fn timer_install_section_wantedby_timers_target() {
    assert!(TIMER_UNIT.contains("[Install]"));
    assert!(TIMER_UNIT.contains("WantedBy=timers.target"));
}

#[test]
fn wrapper_has_shebang_and_strict_mode() {
    assert!(WRAPPER.starts_with("#!/bin/bash"));
    assert!(WRAPPER.contains("set -euo pipefail"));
}

#[test]
fn wrapper_uses_du_for_directory_sizes() {
    assert!(
        WRAPPER.contains("du -sb"),
        "wrapper must use du -sb for bytes-accurate per-directory size"
    );
}

#[test]
fn wrapper_uses_df_for_filesystem_state() {
    assert!(
        WRAPPER.contains("df -B1") && WRAPPER.contains("--output=avail"),
        "wrapper must use df -B1 --output=avail for free-bytes"
    );
}

#[test]
fn wrapper_uses_atomic_tempfile_rename() {
    assert!(WRAPPER.contains("mktemp"));
    assert!(WRAPPER.contains("mv -f"));
}

#[test]
fn wrapper_emits_failure_sentinel() {
    assert!(WRAPPER.contains("selfdef_disk_usage_textfile_emit_failed"));
    assert!(WRAPPER.contains("command -v du"));
}

#[test]
fn wrapper_emits_all_canonical_gauges() {
    for required in [
        "selfdef_disk_usage_lib_bytes",
        "selfdef_disk_usage_log_bytes",
        "selfdef_disk_usage_var_log_bytes",
        "selfdef_disk_usage_textfile_collector_bytes",
        "selfdef_disk_usage_var_free_bytes",
        "selfdef_disk_usage_var_used_percent",
        "selfdef_disk_usage_last_run_unix",
        "selfdef_disk_usage_textfile_emit_failed",
    ] {
        assert!(
            WRAPPER.contains(required),
            "wrapper must emit gauge {required}"
        );
    }
}

#[test]
fn wrapper_measures_4_canonical_paths() {
    // Drift-catch: the 4 paths the operator-visible audit depends on.
    for path in [
        "/var/lib/selfdef",
        "/var/log/selfdef",
        "/var/log",
        "/var/lib/node_exporter/textfile_collector",
    ] {
        assert!(WRAPPER.contains(path), "wrapper must measure path {path}");
    }
}

#[test]
fn wrapper_documents_disk_fill_attack_purpose() {
    assert!(
        WRAPPER.contains("disk-fill"),
        "wrapper docstring must explain disk-fill-attack detection"
    );
}

#[test]
fn wrapper_handles_missing_path_gracefully() {
    // Missing path → 0 bytes (honest about absence), not sentinel.
    assert!(
        WRAPPER.contains("echo 0"),
        "wrapper must echo 0 for missing paths (not sentinel)"
    );
}
