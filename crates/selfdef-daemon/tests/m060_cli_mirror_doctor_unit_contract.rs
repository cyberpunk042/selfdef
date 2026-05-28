//! M060 cli-mirror-doctor systemd unit + timer — contract test.
//!
//! Locks the shape of the observer-side units (timer + service) that
//! drive `selfdefctl cli-mirror doctor --textfile PATH` on a 60s
//! cadence. Companion to the m060_cli_mirror_emit_unit_contract.rs
//! for the producer-side one-shot.
//!
//! No systemd / dpkg here — both unit files are include_str!()'d and
//! grepped for the right clauses.

const DOCTOR_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-cli-mirror-doctor.service");
const DOCTOR_TIMER: &str =
    include_str!("../../../packaging/systemd/selfdef-cli-mirror-doctor.timer");

#[test]
fn doctor_service_invokes_cli_mirror_doctor_with_textfile() {
    assert!(
        DOCTOR_UNIT.contains("/usr/bin/selfdefctl cli-mirror doctor --textfile"),
        "doctor service must invoke the textfile-emitting verb shipped \
         in selfdef-cli main.rs (CliMirrorAction::Doctor with textfile set)"
    );
}

#[test]
fn doctor_service_writes_to_textfile_collector_dir() {
    // The path MUST match the canonical node_exporter
    // textfile_collector convention so a stock Prometheus setup
    // picks the metric up without configuration.
    assert!(
        DOCTOR_UNIT.contains("/var/lib/node_exporter/textfile_collector/selfdef-cli-mirror.prom"),
        "doctor service must write to the node_exporter textfile_collector \
         default path so a stock Prometheus config picks the metric up"
    );
}

#[test]
fn doctor_service_treats_warn_and_fail_exit_as_success() {
    // The doctor verb exits 1 (WARN) or 2 (FAIL) when the chain is
    // degraded — those signals are CAPTURED IN THE METRIC, not unit
    // failure. SuccessExitStatus=0 1 2 prevents systemd from masking
    // successive runs.
    assert!(
        DOCTOR_UNIT.contains("SuccessExitStatus=0 1 2"),
        "doctor service must declare SuccessExitStatus=0 1 2 — the \
         doctor's degraded/failed exit codes are the signal we WANT \
         in Prometheus, not unit failure"
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
        "doctor service must restrict writes to the textfile_collector dir; \
         resident store + everything else is read-only from this unit"
    );
    // Must NOT have write access to the cli-mirror resident store.
    assert!(
        !DOCTOR_UNIT.contains("ReadWritePaths=/var/lib/selfdef"),
        "doctor service must NOT have write access to /var/lib/selfdef — \
         that's the producer's job"
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
    // Cadence chosen so the textfile is always recent for the next
    // Prometheus scrape (default 15-30s interval). Changing this
    // requires updating the alert rules' `for:` windows.
    assert!(
        DOCTOR_TIMER.contains("OnUnitActiveSec=60s"),
        "timer cadence must be 60s; alert rules tuned to this interval"
    );
    assert!(
        DOCTOR_TIMER.contains("OnBootSec=60s"),
        "timer must have a boot delay so it doesn't pile up with sibling one-shots"
    );
}

#[test]
fn doctor_timer_binds_to_the_doctor_service() {
    assert!(
        DOCTOR_TIMER.contains("Unit=selfdef-cli-mirror-doctor.service"),
        "timer's Unit= must point at the doctor service (drift would mean \
         the timer fires the wrong thing — silent observability outage)"
    );
}

#[test]
fn doctor_timer_install_section_wantedby_timers_target() {
    assert!(DOCTOR_TIMER.contains("[Install]"));
    assert!(DOCTOR_TIMER.contains("WantedBy=timers.target"));
}

#[test]
fn doctor_unit_environment_override_matches_resident_store_default() {
    // The doctor reads the SAME resident store the producer one-shot
    // writes. If these two units' Environment= drift, the doctor
    // reports the wrong file's state — silent regression on the
    // operator's observability surface.
    use selfdef_cli_mirror::DEFAULT_STATE_PATH;
    let line = format!("Environment=SELFDEF_CLI_MIRROR_PATH={DEFAULT_STATE_PATH}");
    assert!(
        DOCTOR_UNIT.contains(&line),
        "doctor service Environment=SELFDEF_CLI_MIRROR_PATH must equal the \
         crate const ({DEFAULT_STATE_PATH}) — drift means the doctor reads \
         a different resident store than the producer wrote"
    );
}
