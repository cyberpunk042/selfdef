//! selfdefd.service config pre-flight — contract test (SDD-002).
//!
//! The unit must validate the config in an `ExecStartPre` before the real
//! `ExecStart`, so a bad config fails the unit cleanly at pre-start instead
//! of crash-looping under `Restart=on-failure`. Locks that wiring (and the
//! ordering) so a future unit edit can't silently drop the guard.

const UNIT: &str = include_str!("../../../packaging/systemd/selfdefd.service");

#[test]
fn unit_validates_config_in_execstartpre() {
    assert!(
        UNIT.contains(
            "ExecStartPre=/usr/bin/selfdefd --config /etc/selfdef/selfdef.toml --validate"
        ),
        "selfdefd.service must pre-flight the config with `selfdefd --validate` \
         in ExecStartPre:\n{UNIT}"
    );
}

#[test]
fn execstartpre_precedes_execstart() {
    let pre = UNIT
        .find("ExecStartPre=/usr/bin/selfdefd")
        .expect("ExecStartPre present");
    let start = UNIT
        .find("ExecStart=/usr/bin/selfdefd --config")
        .expect("ExecStart present");
    assert!(
        pre < start,
        "ExecStartPre (validate) must come before ExecStart so a bad config \
         is caught before the daemon is launched"
    );
}

#[test]
fn unit_sets_owner_only_umask() {
    // UMask=0077 makes every daemon-created file owner-only (0600/0700) by
    // default — the hot store `state.sqlite` + its `-wal`/`-shm` siblings, the
    // escalations db, any state file written without an explicit mode. Without
    // it the mode is the inherited umask (typically 0022 → 0644 = a
    // world-readable forensic store). The /metrics + /v1 unix socket is
    // unaffected (its mode is set explicitly post-bind via set_permissions),
    // so this can't loosen the socket. Lock it so a future unit edit can't
    // silently drop the owner-only default. (F-2026-102 follow-up.)
    assert!(
        UNIT.contains("UMask=0077"),
        "selfdefd.service must set UMask=0077 so daemon-created files (incl. the \
         hot store) are owner-only, not world-readable under a permissive umask:\n{UNIT}"
    );
}

#[test]
fn preflight_targets_the_same_config_as_execstart() {
    // Both lines must reference /etc/selfdef/selfdef.toml — validating a
    // different file than the one ExecStart loads would defeat the guard.
    assert_eq!(
        UNIT.matches("--config /etc/selfdef/selfdef.toml").count(),
        2,
        "ExecStartPre and ExecStart must validate + run the SAME config path:\n{UNIT}"
    );
}
