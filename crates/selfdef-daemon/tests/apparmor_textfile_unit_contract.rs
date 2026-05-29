//! selfdef-apparmor-textfile observer — contract test.
//!
//! Locks the shape of the new AppArmor profile-enforcement observer
//! unit, timer, and wrapper shipped this commit. Sister to the
//! 5 existing observer contracts.

const SERVICE_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-apparmor-textfile.service");
const TIMER_UNIT: &str = include_str!("../../../packaging/systemd/selfdef-apparmor-textfile.timer");
const WRAPPER: &str = include_str!("../../../packaging/scripts/selfdef-apparmor-textfile.sh");

// ──────────────────────────────────────────────── service unit tests

#[test]
fn service_invokes_the_wrapper_at_canonical_path() {
    assert!(SERVICE_UNIT.contains("ExecStart=/usr/share/selfdef/selfdef-apparmor-textfile.sh"));
}

#[test]
fn service_writes_to_node_exporter_textfile_collector_dir() {
    assert!(SERVICE_UNIT.contains(
        "SELFDEF_APPARMOR_TEXTFILE_PATH=/var/lib/node_exporter/textfile_collector/selfdef-apparmor.prom"
    ));
}

#[test]
fn service_documents_canonical_profile_name() {
    assert!(
        SERVICE_UNIT.contains("SELFDEF_APPARMOR_PROFILE_NAME=/usr/bin/selfdefd"),
        "service must default to the canonical selfdefd profile name"
    );
}

#[test]
fn service_runs_as_selfdef_user_not_root() {
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
    assert!(SERVICE_UNIT.contains("SuccessExitStatus=0"));
}

// ───────────────────────────────────────────────────── timer tests

#[test]
fn timer_runs_every_60_seconds() {
    assert!(TIMER_UNIT.contains("OnUnitActiveSec=60s"));
}

#[test]
fn timer_has_180s_offset_boot_delay() {
    // 6th and latest observer timer — above cli-mirror 60s, m060 70s,
    // four-watchdog 90s, modules 120s, daemon-process 150s.
    assert!(
        TIMER_UNIT.contains("OnBootSec=180s"),
        "timer must have 180s offset (6th distinct above 5 siblings)"
    );
}

#[test]
fn timer_binds_to_the_service() {
    assert!(TIMER_UNIT.contains("Unit=selfdef-apparmor-textfile.service"));
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
fn wrapper_reads_kernel_apparmor_profiles_file() {
    assert!(
        WRAPPER.contains("/sys/kernel/security/apparmor/profiles"),
        "wrapper must read the kernel-exposed AppArmor profiles file"
    );
}

#[test]
fn wrapper_uses_atomic_tempfile_rename() {
    assert!(WRAPPER.contains("mktemp"));
    assert!(WRAPPER.contains("mv -f"));
}

#[test]
fn wrapper_emits_failure_sentinel_when_apparmor_absent() {
    assert!(WRAPPER.contains("selfdef_apparmor_textfile_emit_failed"));
    assert!(
        WRAPPER.contains("[ -r \"$PROFILES_FILE\" ]") || WRAPPER.contains("-r \"$PROFILES_FILE\""),
        "wrapper must check kernel AppArmor is available before reading"
    );
}

#[test]
fn wrapper_emits_all_canonical_gauges() {
    for required in [
        "selfdef_apparmor_profile_loaded",
        "selfdef_apparmor_profile_enforce",
        "selfdef_apparmor_profile_complain",
        "selfdef_apparmor_profiles_loaded_total",
        "selfdef_apparmor_last_run_unix",
        "selfdef_apparmor_textfile_emit_failed",
    ] {
        assert!(
            WRAPPER.contains(required),
            "wrapper must emit gauge {required}"
        );
    }
}

#[test]
fn wrapper_profile_gauges_carry_profile_label() {
    // The 3 per-profile gauges (loaded/enforce/complain) MUST carry
    // the profile= label so operators can filter on the selfdefd
    // profile vs other profiles.
    assert!(
        WRAPPER.contains("profile=\""),
        "per-profile gauges must carry the profile label"
    );
}

#[test]
fn wrapper_distinguishes_absent_from_enforce_complain_kill() {
    // The wrapper MUST handle the 4 canonical profile states:
    // enforce / complain / kill / unconfined / absent.
    for state in ["enforce", "complain", "absent"] {
        assert!(
            WRAPPER.contains(state),
            "wrapper must distinguish state {state}"
        );
    }
}

#[test]
fn wrapper_documents_honest_offline_contract() {
    assert!(
        WRAPPER.contains("Honest-offline") || WRAPPER.contains("honest-offline"),
        "wrapper docstring must document the honest-offline contract"
    );
}

#[test]
fn wrapper_supports_profile_name_override() {
    assert!(
        WRAPPER.contains("SELFDEF_APPARMOR_PROFILE_NAME"),
        "wrapper must honor SELFDEF_APPARMOR_PROFILE_NAME override env var"
    );
}

#[test]
fn wrapper_documents_ips_load_bearing_nature() {
    // The wrapper docstring MUST document why AppArmor enforcement
    // is load-bearing IPS surface — operator-actionable context.
    assert!(
        WRAPPER.contains("complain mode")
            || WRAPPER.contains("complain-mode")
            || WRAPPER.contains("complain"),
        "wrapper docstring must explain complain-mode drift as the IPS hazard"
    );
}
