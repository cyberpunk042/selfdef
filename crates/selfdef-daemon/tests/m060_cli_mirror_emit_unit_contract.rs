//! M060 cli-mirror emit systemd unit — contract test.
//!
//! Guards the cross-binary contract between the operator-controlled
//! producer (`packaging/systemd/selfdef-cli-mirror-emit.service`) and
//! the daemon-side consumer
//! (`selfdef-daemon::cli_mirror_publisher::resident_store_path`):
//! both honor `SELFDEF_CLI_MIRROR_PATH` + share the
//! `/var/lib/selfdef/cli-mirror.json` default. Drift in either side
//! would silently regress the resident-store path back to the
//! shell-out fallback.
//!
//! This test reads the unit file directly (no systemd / no
//! filesystem mutation) and asserts the path constants visible in
//! the shipped artifact match what the daemon expects.

use selfdef_cli_mirror::DEFAULT_STATE_PATH;

const EMIT_UNIT: &str = include_str!("../../../packaging/systemd/selfdef-cli-mirror-emit.service");

#[test]
fn unit_invokes_selfdefctl_cli_mirror_snapshot_with_output() {
    assert!(
        EMIT_UNIT.contains("/usr/bin/selfdefctl cli-mirror snapshot --output"),
        "unit must invoke the producer verb shipped in selfdef-cli main.rs \
         (CliMirrorAction::Snapshot with output set)"
    );
}

#[test]
fn unit_environment_matches_crate_default_state_path() {
    // The Environment= clause sets the same default the daemon's
    // resident_store_path() falls back to. Drift here would silently
    // route producer + consumer to different files.
    let default_env_line = format!("Environment=SELFDEF_CLI_MIRROR_PATH={DEFAULT_STATE_PATH}");
    assert!(
        EMIT_UNIT.contains(&default_env_line),
        "unit Environment= must equal selfdef_cli_mirror::DEFAULT_STATE_PATH \
         ({DEFAULT_STATE_PATH}) — daemon's cli_mirror_publisher honors the \
         same env var"
    );
}

#[test]
fn unit_runs_as_selfdef_user_not_root() {
    // /var/lib/selfdef is owned by selfdef:selfdef per debian postinst.
    // Running as a different user would create cli-mirror.json with
    // wrong perms + the daemon (selfdef user) couldn't re-read on a
    // refresh.
    assert!(EMIT_UNIT.contains("User=selfdef"));
    assert!(EMIT_UNIT.contains("Group=selfdef"));
}

#[test]
fn unit_is_one_shot() {
    assert!(EMIT_UNIT.contains("Type=oneshot"));
}

#[test]
fn unit_hardening_matches_sibling_one_shots() {
    // Mirrors selfdef-doctor.service's posture — these are the
    // baseline guardrails every selfdef one-shot wears. Drift would
    // mean a regression in the local-attack-surface contract.
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
            EMIT_UNIT.contains(required),
            "unit missing required hardening clause: {required}"
        );
    }
}

#[test]
fn unit_grants_write_access_only_to_state_dir() {
    // Producer writes the resident artifact inside /var/lib/selfdef
    // (atomic tempfile + rename in the same directory). The systemd
    // sandbox MUST permit that path + ONLY that path.
    assert!(EMIT_UNIT.contains("ReadWritePaths=/var/lib/selfdef"));
}

#[test]
fn unit_has_no_network_surface() {
    // Pure local file operation — no IPC, no resolver, no socket.
    assert!(
        EMIT_UNIT.contains("PrivateNetwork=true"),
        "unit must run with PrivateNetwork=true — the producer is \
         a pure-local file operation"
    );
    assert!(
        EMIT_UNIT.contains("RestrictAddressFamilies=AF_UNIX"),
        "unit must restrict address families to AF_UNIX"
    );
}

#[test]
fn unit_install_section_present_for_systemctl_enable() {
    assert!(EMIT_UNIT.contains("[Install]"));
    assert!(EMIT_UNIT.contains("WantedBy=multi-user.target"));
}
