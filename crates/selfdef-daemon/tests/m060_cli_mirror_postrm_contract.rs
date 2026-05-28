//! M060 cli-mirror — debian postrm lifecycle contract.
//!
//! Locks the postrm hook's handling of the
//! `selfdef-cli-mirror-emit.service` one-shot across the two
//! lifecycle paths an operator can hit (`remove` = un-install but
//! keep config, `purge` = full wipe). Pre-existing per-watchdog
//! hooks (sovereign-guard, selfdef-guardian, selfdef-scheduler) are
//! the template — the cli-mirror handling must match the same
//! shape so an operator who's read one knows what the others do.
//!
//! No systemd / no dpkg here: the test reads the shipped postrm
//! script as a string + asserts the right ExecStop /
//! disable / remove invocations appear in the right `case`-arm.

const POSTRM: &str = include_str!("../../../packaging/debian/postrm");

/// Returns the `case` arm body for the given dpkg action, lowercase.
/// Returns `None` when the arm is missing entirely.
fn case_arm(action: &str) -> Option<&'static str> {
    // The postrm uses lowercase `case "$1" in` arms separated by `;;`.
    // For "purge" the arm body starts after "    purge)" and ends at
    // the next ";;". Same shape for "remove".
    let needle = format!("    {action})\n");
    let start = POSTRM.find(&needle)?;
    let after = &POSTRM[start + needle.len()..];
    let end = after.find(";;")?;
    Some(&after[..end])
}

#[test]
fn purge_arm_exists() {
    assert!(
        case_arm("purge").is_some(),
        "postrm must handle `purge` (full uninstall + state wipe)"
    );
}

#[test]
fn remove_arm_exists() {
    assert!(
        case_arm("remove").is_some(),
        "postrm must handle `remove` (uninstall, keep config)"
    );
}

#[test]
fn purge_disables_cli_mirror_emit() {
    let arm = case_arm("purge").expect("purge arm");
    assert!(
        arm.contains("systemctl disable selfdef-cli-mirror-emit.service"),
        "purge MUST disable the cli-mirror-emit one-shot (else dpkg \
         leaves a next-boot trigger pointing at the removed binary). \
         Arm body:\n{arm}"
    );
}

#[test]
fn purge_stops_cli_mirror_emit() {
    let arm = case_arm("purge").expect("purge arm");
    assert!(
        arm.contains("systemctl stop selfdef-cli-mirror-emit.service"),
        "purge MUST stop the cli-mirror-emit one-shot. Arm body:\n{arm}"
    );
}

#[test]
fn purge_removes_drop_in_override_dir() {
    // Operator drop-ins under /etc/systemd/system/<unit>.d/override.conf
    // are operator-owned but get unreferenceable post-purge (the unit
    // they override is gone). Remove the dir so it doesn't accumulate
    // across install/purge cycles.
    let arm = case_arm("purge").expect("purge arm");
    assert!(
        arm.contains("rm -rf /etc/systemd/system/selfdef-cli-mirror-emit.service.d"),
        "purge MUST remove the drop-in override dir. Arm body:\n{arm}"
    );
}

#[test]
fn purge_resident_store_falls_under_var_lib_wipe() {
    // The resident artifact is /var/lib/selfdef/cli-mirror.json.
    // The existing `rm -rf /var/lib/selfdef` line wipes everything
    // under there including the resident store — verify that line is
    // still present + comes BEFORE any cli-mirror-specific handling
    // (so the contract isn't accidentally broken by adding cli-mirror-
    // specific cleanup elsewhere that runs first).
    let arm = case_arm("purge").expect("purge arm");
    let wipe = arm
        .find("rm -rf /var/lib/selfdef")
        .expect("purge must wipe /var/lib/selfdef");
    let cli = arm.find("selfdef-cli-mirror-emit").unwrap_or(usize::MAX);
    assert!(
        wipe < cli,
        "the /var/lib/selfdef wipe must come BEFORE cli-mirror-emit handling \
         (so the resident store removal isn't accidentally short-circuited)"
    );
}

#[test]
fn remove_stops_but_does_not_disable_cli_mirror_emit() {
    // `remove` = uninstall but keep config. The operator may reinstall
    // (= upgrade path) and expect the unit to come back enabled if
    // they had enabled it. So we STOP (kills any in-flight emit) but
    // DON'T disable (preserves the wanted-by state across reinstall).
    let arm = case_arm("remove").expect("remove arm");
    assert!(
        arm.contains("systemctl stop selfdef-cli-mirror-emit.service"),
        "remove MUST stop the cli-mirror-emit one-shot (the ExecStart \
         references the about-to-be-removed selfdefctl). Arm body:\n{arm}"
    );
    assert!(
        !arm.contains("systemctl disable selfdef-cli-mirror-emit.service"),
        "remove MUST NOT disable the cli-mirror-emit unit — that's the \
         purge path. Disabling here would break the reinstall=upgrade \
         contract. Arm body:\n{arm}"
    );
}

#[test]
fn purge_arm_matches_sibling_unit_template() {
    // The cli-mirror-emit handling must follow the same shape as the
    // sovereign-guard / selfdef-guardian / selfdef-scheduler handling
    // in the same postrm. This is the operator-mental-model contract
    // — reading any one arm explains the others.
    let arm = case_arm("purge").expect("purge arm");
    for sibling_unit in [
        "sovereign-guard.service",
        "selfdef-guardian.service",
        "selfdef-scheduler.service",
        "selfdef-cli-mirror-emit.service",
        "selfdef-cli-mirror-doctor.timer",
        "selfdef-cli-mirror-doctor.service",
    ] {
        assert!(
            arm.contains(&format!("systemctl disable {sibling_unit}")),
            "purge arm must `systemctl disable {sibling_unit}` — \
             missing in the same shape as its peers"
        );
        assert!(
            arm.contains(&format!("systemctl stop {sibling_unit}")),
            "purge arm must `systemctl stop {sibling_unit}` — \
             missing in the same shape as its peers"
        );
    }
}

#[test]
fn purge_handles_chain_doctor_timer_with_same_shape() {
    // The chain-wide m060-doctor.timer must get the same
    // disable+stop+drop-in-cleanup treatment as the cli-mirror sibling.
    let arm = case_arm("purge").expect("purge arm");
    for unit in ["selfdef-m060-doctor.timer", "selfdef-m060-doctor.service"] {
        assert!(
            arm.contains(&format!("systemctl disable {unit}")),
            "purge arm must disable {unit}"
        );
        assert!(
            arm.contains(&format!("systemctl stop {unit}")),
            "purge arm must stop {unit}"
        );
    }
    assert!(
        arm.contains("rm -rf /etc/systemd/system/selfdef-m060-doctor.service.d"),
        "purge must remove the m060-doctor service drop-in dir"
    );
    assert!(
        arm.contains("rm -rf /etc/systemd/system/selfdef-m060-doctor.timer.d"),
        "purge must remove the m060-doctor timer drop-in dir"
    );
    assert!(
        arm.contains("rm -f /var/lib/node_exporter/textfile_collector/selfdef-m060-doctor.prom"),
        "purge must remove the chain-wide doctor's textfile artifact"
    );
}

#[test]
fn remove_stops_chain_doctor_timer_without_disabling() {
    let arm = case_arm("remove").expect("remove arm");
    assert!(
        arm.contains("systemctl stop selfdef-m060-doctor.timer"),
        "remove must stop the chain-doctor timer"
    );
    assert!(
        !arm.contains("systemctl disable selfdef-m060-doctor.timer"),
        "remove must NOT disable the chain-doctor timer (reinstall=upgrade)"
    );
}

#[test]
fn purge_removes_doctor_textfile_artifact() {
    // The doctor systemd timer writes
    // /var/lib/node_exporter/textfile_collector/selfdef-cli-mirror.prom
    // — on purge that file must go too (the dir itself is operator-
    // controlled; we touch only the file we produced).
    let arm = case_arm("purge").expect("purge arm");
    assert!(
        arm.contains("rm -f /var/lib/node_exporter/textfile_collector/selfdef-cli-mirror.prom"),
        "purge must remove the doctor's textfile artifact; arm:\n{arm}"
    );
}

#[test]
fn remove_stops_doctor_timer_without_disabling() {
    // Same reinstall=upgrade contract as cli-mirror-emit: stop on
    // bare remove (selfdefctl is going away), don't disable
    // (preserve enabled state for reinstall).
    let arm = case_arm("remove").expect("remove arm");
    assert!(
        arm.contains("systemctl stop selfdef-cli-mirror-doctor.timer"),
        "remove must stop the doctor timer (selfdefctl is being removed); arm:\n{arm}"
    );
    assert!(
        !arm.contains("systemctl disable selfdef-cli-mirror-doctor.timer"),
        "remove must NOT disable the doctor timer (reinstall=upgrade contract); arm:\n{arm}"
    );
}

#[test]
fn purge_triggers_daemon_reload_after_unit_removal() {
    // Bare necessity for systemd to forget the unit cleanly. Present
    // in the original postrm; the cli-mirror handling must land
    // before this final reload so all the disable/stop calls are
    // settled by the time we tell systemd to re-scan.
    let arm = case_arm("purge").expect("purge arm");
    let cli = arm
        .find("selfdef-cli-mirror-emit")
        .expect("cli-mirror arm body");
    let reload = arm
        .find("systemctl daemon-reload")
        .expect("daemon-reload at end of purge arm");
    assert!(
        cli < reload,
        "cli-mirror-emit disable/stop MUST run BEFORE the trailing \
         daemon-reload so systemd re-scans a clean state"
    );
}
