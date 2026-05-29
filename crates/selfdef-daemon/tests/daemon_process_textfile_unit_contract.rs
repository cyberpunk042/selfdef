//! selfdef-daemon-process-textfile observer — contract test.
//!
//! Locks the shape of the new daemon process-state observer unit,
//! timer, and wrapper shipped this commit. Sister to the existing
//! M060 cli-mirror plus m060-chain plus four-watchdog plus
//! modules-textfile doctor observer contracts.
//!
//! Process-state observability is a load-bearing IPS surface —
//! memory leak / FD exhaustion / restart loop detection lives here.
//! Drift in this observer would silently weaken the IPS spine's
//! self-monitoring posture.

const SERVICE_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-daemon-process-textfile.service");
const TIMER_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-daemon-process-textfile.timer");
const WRAPPER: &str = include_str!("../../../packaging/scripts/selfdef-daemon-process-textfile.sh");

// ──────────────────────────────────────────────── service unit tests

#[test]
fn service_invokes_the_wrapper_at_canonical_path() {
    assert!(
        SERVICE_UNIT.contains("ExecStart=/usr/share/selfdef/selfdef-daemon-process-textfile.sh"),
        "service must invoke the canonical wrapper path"
    );
}

#[test]
fn service_writes_to_node_exporter_textfile_collector_dir() {
    assert!(
        SERVICE_UNIT.contains(
            "SELFDEF_DAEMON_PROCESS_TEXTFILE_PATH=/var/lib/node_exporter/textfile_collector/selfdef-daemon-process.prom"
        ),
        "service must export the canonical textfile path"
    );
}

#[test]
fn service_orders_after_selfdefd() {
    // The process-state observer reads selfdefd's PID — must order
    // After=selfdefd.service so it doesn't fire before selfdefd is up.
    assert!(
        SERVICE_UNIT.contains("selfdefd.service"),
        "service must order After=selfdefd.service"
    );
}

#[test]
fn service_runs_as_selfdef_user_not_root() {
    assert!(SERVICE_UNIT.contains("User=selfdef"));
    assert!(SERVICE_UNIT.contains("Group=selfdef"));
}

#[test]
fn service_grants_write_only_to_textfile_collector() {
    assert!(
        SERVICE_UNIT.contains("ReadWritePaths=/var/lib/node_exporter/textfile_collector"),
        "service must restrict writes to the textfile_collector dir"
    );
    assert!(
        !SERVICE_UNIT.contains("ReadWritePaths=/var/lib/selfdef"),
        "service must NOT have write access to /var/lib/selfdef"
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
            "service missing required hardening clause: {required}"
        );
    }
}

#[test]
fn service_timeout_caps_runtime() {
    assert!(SERVICE_UNIT.contains("TimeoutStartSec=30s"));
}

#[test]
fn service_treats_success_as_success_only() {
    // Process state either reads or it doesn't — no severity ladder.
    // Distinct from doctor observers which use SuccessExitStatus=0 1 2.
    assert!(
        SERVICE_UNIT.contains("SuccessExitStatus=0"),
        "service must declare SuccessExitStatus=0 only"
    );
}

// ───────────────────────────────────────────────────── timer tests

#[test]
fn timer_runs_every_60_seconds() {
    assert!(
        TIMER_UNIT.contains("OnUnitActiveSec=60s"),
        "timer cadence must be 60s; matches sibling observers"
    );
}

#[test]
fn timer_has_offset_boot_delay() {
    // 150s offset — above cli-mirror 60s, m060 70s, four-watchdog 90s,
    // modules 120s. 5 observer timers, 5 distinct boot offsets.
    assert!(
        TIMER_UNIT.contains("OnBootSec=150s"),
        "timer must have 150s offset boot delay (above all 4 sibling timers)"
    );
}

#[test]
fn timer_binds_to_the_service() {
    assert!(TIMER_UNIT.contains("Unit=selfdef-daemon-process-textfile.service"));
}

#[test]
fn timer_randomized_delay_for_fleet_decorrelation() {
    assert!(TIMER_UNIT.contains("RandomizedDelaySec="));
}

#[test]
fn timer_install_section_wantedby_timers_target() {
    assert!(TIMER_UNIT.contains("[Install]"));
    assert!(TIMER_UNIT.contains("WantedBy=timers.target"));
}

// ────────────────────────────────────────────── wrapper contract tests

#[test]
fn wrapper_has_shebang() {
    assert!(WRAPPER.starts_with("#!/bin/bash"));
}

#[test]
fn wrapper_uses_strict_mode() {
    assert!(WRAPPER.contains("set -euo pipefail"));
}

#[test]
fn wrapper_resolves_pid_via_systemctl() {
    assert!(
        WRAPPER.contains("systemctl show -p MainPID"),
        "wrapper must resolve selfdefd PID via systemctl show"
    );
}

#[test]
fn wrapper_reads_proc_fs_for_process_state() {
    assert!(WRAPPER.contains("/proc/$pid/status"));
    assert!(WRAPPER.contains("/proc/$pid/stat"));
    assert!(WRAPPER.contains("/proc/$pid/fd/"));
}

#[test]
fn wrapper_uses_atomic_tempfile_rename() {
    assert!(WRAPPER.contains("mktemp"));
    assert!(WRAPPER.contains("mv -f"));
}

#[test]
fn wrapper_emits_failure_sentinel_when_daemon_absent() {
    assert!(WRAPPER.contains("selfdef_daemon_process_textfile_emit_failed"));
    // Honest-offline: when MainPID is 0 (daemon not running), sentinel.
    assert!(
        WRAPPER.contains("MainPID=0") || WRAPPER.contains("\"$pid\" = \"0\""),
        "wrapper must treat MainPID=0 as honest-offline"
    );
}

#[test]
fn wrapper_emits_all_canonical_gauges() {
    for required in [
        "selfdef_daemon_process_memory_rss_bytes",
        "selfdef_daemon_process_memory_vsize_bytes",
        "selfdef_daemon_process_open_fds",
        "selfdef_daemon_process_threads",
        "selfdef_daemon_process_uptime_seconds",
        "selfdef_daemon_process_restart_count",
        "selfdef_daemon_process_last_run_unix",
        "selfdef_daemon_process_textfile_emit_failed",
    ] {
        assert!(
            WRAPPER.contains(required),
            "wrapper must emit gauge {required}"
        );
    }
}

#[test]
fn wrapper_uses_n_restarts_for_restart_count() {
    // Restart count comes from systemd's NRestarts property — drift
    // to e.g. journalctl grep would silently miss restarts.
    assert!(
        WRAPPER.contains("NRestarts"),
        "wrapper must read NRestarts via systemctl show"
    );
}

#[test]
fn wrapper_documents_honest_offline_contract() {
    assert!(
        WRAPPER.contains("Honest-offline") || WRAPPER.contains("honest-offline"),
        "wrapper docstring must document the honest-offline contract"
    );
}

#[test]
fn wrapper_supports_daemon_unit_override() {
    // Operators using a non-standard unit name (e.g. selfdefd@instance)
    // must be able to override via SELFDEF_DAEMON_UNIT.
    assert!(
        WRAPPER.contains("SELFDEF_DAEMON_UNIT"),
        "wrapper must honor SELFDEF_DAEMON_UNIT override env var"
    );
}

#[test]
fn wrapper_restart_count_is_counter_type() {
    // NRestarts is monotonic — declare it as a Prometheus counter so
    // Prometheus knows to use rate() correctly.
    assert!(
        WRAPPER.contains("# TYPE selfdef_daemon_process_restart_count counter"),
        "restart_count gauge must be declared as TYPE counter"
    );
}
