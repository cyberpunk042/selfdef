//! M060 chain-wide doctor systemd unit + timer — contract test.
//!
//! Locks the shape of the chain-wide observer units that drive
//! `selfdefctl m060-doctor --textfile PATH` on a 60s cadence.
//! Companion to m060_cli_mirror_doctor_unit_contract.rs (which covers
//! the D-CLI-specific observer).

const DOCTOR_UNIT: &str = include_str!("../../../packaging/systemd/selfdef-m060-doctor.service");
const DOCTOR_TIMER: &str = include_str!("../../../packaging/systemd/selfdef-m060-doctor.timer");

#[test]
fn doctor_service_invokes_m060_doctor_with_textfile() {
    assert!(
        DOCTOR_UNIT.contains("/usr/bin/selfdefctl m060-doctor --textfile"),
        "doctor service must invoke the textfile-emitting verb"
    );
}

#[test]
fn doctor_service_writes_to_textfile_collector_dir() {
    assert!(
        DOCTOR_UNIT.contains("/var/lib/node_exporter/textfile_collector/selfdef-m060-doctor.prom"),
        "doctor service must write to the node_exporter textfile_collector \
         convention so Prometheus picks the metric up out of the box"
    );
}

#[test]
fn doctor_service_treats_inconsistency_exit_as_success() {
    // m060-doctor exits 1 when a chain inconsistency is detected
    // (resident present but published absent). That signal is
    // CAPTURED IN THE METRIC, not unit failure. SuccessExitStatus=0 1
    // prevents systemd from masking successive runs.
    assert!(
        DOCTOR_UNIT.contains("SuccessExitStatus=0 1"),
        "doctor service must declare SuccessExitStatus=0 1 — the \
         exit code reflects chain state, not unit health"
    );
}

#[test]
fn doctor_service_runs_as_selfdef_user_not_root() {
    assert!(DOCTOR_UNIT.contains("User=selfdef"));
    assert!(DOCTOR_UNIT.contains("Group=selfdef"));
}

#[test]
fn doctor_service_grants_write_only_to_textfile_collector() {
    assert!(
        DOCTOR_UNIT.contains("ReadWritePaths=/var/lib/node_exporter/textfile_collector"),
        "doctor service must restrict writes to the textfile_collector dir"
    );
    assert!(
        !DOCTOR_UNIT.contains("ReadWritePaths=/var/lib/selfdef"),
        "doctor service must NOT have write access to /var/lib/selfdef — \
         that's the producer's job; the doctor is a pure observer"
    );
}

#[test]
fn doctor_service_hardening_matches_sibling_units() {
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
    ] {
        assert!(
            DOCTOR_UNIT.contains(required),
            "doctor service missing required hardening clause: {required}"
        );
    }
}

#[test]
fn doctor_timer_runs_every_60_seconds() {
    assert!(
        DOCTOR_TIMER.contains("OnUnitActiveSec=60s"),
        "timer cadence must be 60s; alert rules tuned to this interval"
    );
}

#[test]
fn doctor_timer_boot_delay_offset_from_sibling() {
    // OnBootSec must differ from the cli-mirror-doctor sibling (60s)
    // so the two observers don't pile up at the exact same boot
    // moment. 70s gives the cli-mirror one a clean 10s window.
    assert!(
        DOCTOR_TIMER.contains("OnBootSec=70s"),
        "timer must have a boot delay offset from sibling observers"
    );
}

#[test]
fn doctor_timer_binds_to_the_doctor_service() {
    assert!(
        DOCTOR_TIMER.contains("Unit=selfdef-m060-doctor.service"),
        "timer's Unit= must point at the doctor service"
    );
}

#[test]
fn doctor_timer_install_section_wantedby_timers_target() {
    assert!(DOCTOR_TIMER.contains("[Install]"));
    assert!(DOCTOR_TIMER.contains("WantedBy=timers.target"));
}
