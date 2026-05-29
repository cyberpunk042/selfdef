//! selfdef-time-sync-textfile observer — contract test.
//!
//! Locks the 11th sibling textfile observer shipped this commit.
//! Surfaces time-sync state so operators detect clock drift before
//! audit-trail timestamps become unreliable.

const SERVICE_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-time-sync-textfile.service");
const TIMER_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-time-sync-textfile.timer");
const WRAPPER: &str = include_str!("../../../packaging/scripts/selfdef-time-sync-textfile.sh");

#[test]
fn service_invokes_the_wrapper_at_canonical_path() {
    assert!(SERVICE_UNIT.contains("ExecStart=/usr/share/selfdef/selfdef-time-sync-textfile.sh"));
}

#[test]
fn service_writes_to_node_exporter_textfile_collector_dir() {
    assert!(SERVICE_UNIT.contains(
        "SELFDEF_TIME_SYNC_TEXTFILE_PATH=/var/lib/node_exporter/textfile_collector/selfdef-time-sync.prom"
    ));
}

#[test]
fn service_runs_as_selfdef_user() {
    assert!(SERVICE_UNIT.contains("User=selfdef"));
    assert!(SERVICE_UNIT.contains("Group=selfdef"));
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
fn timer_has_330s_offset_boot_delay() {
    // 11th sibling timer — above the 10 previous timers.
    assert!(
        TIMER_UNIT.contains("OnBootSec=330s"),
        "timer must have 330s offset (11th distinct above 10 siblings)"
    );
}

#[test]
fn timer_binds_to_the_service() {
    assert!(TIMER_UNIT.contains("Unit=selfdef-time-sync-textfile.service"));
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
fn wrapper_calls_timedatectl_status() {
    assert!(
        WRAPPER.contains("timedatectl status"),
        "wrapper must call timedatectl status"
    );
}

#[test]
fn wrapper_uses_atomic_tempfile_rename() {
    assert!(WRAPPER.contains("mktemp"));
    assert!(WRAPPER.contains("mv -f"));
}

#[test]
fn wrapper_emits_failure_sentinel_when_timedatectl_missing() {
    assert!(WRAPPER.contains("selfdef_time_sync_textfile_emit_failed"));
    assert!(WRAPPER.contains("command -v timedatectl"));
}

#[test]
fn wrapper_emits_all_canonical_gauges() {
    for required in [
        "selfdef_time_sync_synced",
        "selfdef_time_sync_ntp_active",
        "selfdef_time_sync_rtc_local_tz",
        "selfdef_time_sync_drift_seconds",
        "selfdef_time_sync_last_run_unix",
        "selfdef_time_sync_textfile_emit_failed",
    ] {
        assert!(
            WRAPPER.contains(required),
            "wrapper must emit gauge {required}"
        );
    }
}

#[test]
fn wrapper_parses_canonical_timedatectl_fields() {
    // All 3 canonical fields the wrapper extracts from timedatectl
    // output. Drift in any of these names = silently broken parse.
    for field in [
        "System clock synchronized",
        "NTP service",
        "RTC in local TZ",
    ] {
        assert!(WRAPPER.contains(field), "wrapper must parse field {field}");
    }
}

#[test]
fn wrapper_reads_rtc_since_epoch_for_drift() {
    assert!(
        WRAPPER.contains("/sys/class/rtc/rtc0/since_epoch"),
        "wrapper must read /sys/class/rtc/rtc0/since_epoch for drift"
    );
}

#[test]
fn wrapper_computes_absolute_drift() {
    // Drift could be negative — wrapper must take abs() so the
    // gauge is monotonically non-negative.
    assert!(
        WRAPPER.contains("drift_seconds=$(( -drift_seconds ))"),
        "wrapper must compute absolute drift"
    );
}

#[test]
fn wrapper_treats_rtc_local_tz_as_hazard() {
    // RTC in local TZ flips the gauge to 1 (potential drift hazard).
    assert!(
        WRAPPER.contains("rtc_local_val=1"),
        "wrapper must flag RTC local TZ as hazard (gauge=1)"
    );
}

#[test]
fn wrapper_documents_audit_trail_purpose() {
    assert!(
        WRAPPER.contains("audit-trail"),
        "wrapper docstring must explain audit-trail timestamp purpose"
    );
}
