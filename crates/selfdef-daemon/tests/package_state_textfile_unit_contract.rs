//! selfdef-package-state-textfile observer — contract test.
//!
//! Locks the 17th sibling textfile observer shipped this commit.
//! Surfaces apt/dpkg package-state hygiene. Pairs with sshd-config
//! (16th sibling) at the security-baseline axis.

const SERVICE_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-package-state-textfile.service");
const TIMER_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-package-state-textfile.timer");
const WRAPPER: &str = include_str!("../../../packaging/scripts/selfdef-package-state-textfile.sh");

#[test]
fn service_invokes_the_wrapper_at_canonical_path() {
    assert!(
        SERVICE_UNIT.contains("ExecStart=/usr/share/selfdef/selfdef-package-state-textfile.sh")
    );
}

#[test]
fn service_writes_to_node_exporter_textfile_collector_dir() {
    assert!(SERVICE_UNIT.contains(
        "SELFDEF_PACKAGE_STATE_TEXTFILE_PATH=/var/lib/node_exporter/textfile_collector/selfdef-package-state.prom"
    ));
}

#[test]
fn service_runs_as_selfdef_user() {
    assert!(SERVICE_UNIT.contains("User=selfdef"));
    assert!(SERVICE_UNIT.contains("Group=selfdef"));
}

#[test]
fn service_reads_apt_dpkg_state_dirs_readonly() {
    for required in ["/var/lib/apt", "/var/lib/dpkg", "/etc/apt"] {
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
fn service_extends_timeout_to_60s_for_apt_simulation() {
    // apt-get -s upgrade can take 5-30s on busy systems.
    assert!(SERVICE_UNIT.contains("TimeoutStartSec=60s"));
}

#[test]
fn timer_runs_every_60_seconds() {
    assert!(TIMER_UNIT.contains("OnUnitActiveSec=60s"));
}

#[test]
fn timer_has_510s_offset_boot_delay() {
    // 17th sibling — 510s distinct above the 16 prior siblings.
    assert!(
        TIMER_UNIT.contains("OnBootSec=510s"),
        "timer must have 510s offset (17th distinct above 16 siblings)"
    );
}

#[test]
fn timer_binds_to_the_service() {
    assert!(TIMER_UNIT.contains("Unit=selfdef-package-state-textfile.service"));
}

#[test]
fn wrapper_has_shebang_and_strict_mode() {
    assert!(WRAPPER.starts_with("#!/bin/bash"));
    assert!(WRAPPER.contains("set -euo pipefail"));
}

#[test]
fn wrapper_checks_for_dpkg_query_presence() {
    assert!(
        WRAPPER.contains("command -v dpkg-query"),
        "wrapper must honest-offline if dpkg-query missing (rpm hosts)"
    );
}

#[test]
fn wrapper_simulates_apt_upgrade() {
    // apt-get -s upgrade simulates without modifying anything.
    assert!(
        WRAPPER.contains("apt-get -s upgrade"),
        "wrapper must simulate apt upgrade (no actual install)"
    );
}

#[test]
fn wrapper_distinguishes_security_pending() {
    // -security repo lines indicate CVE patches.
    assert!(
        WRAPPER.contains("-security"),
        "wrapper must filter -security repo lines for CVE pending count"
    );
}

#[test]
fn wrapper_reads_var_lib_apt_lists_for_freshness() {
    assert!(
        WRAPPER.contains("/var/lib/apt/lists"),
        "wrapper must read /var/lib/apt/lists/ mtime for apt-update freshness"
    );
}

#[test]
fn wrapper_computes_apt_update_age_in_days() {
    assert!(
        WRAPPER.contains("86400"),
        "wrapper must convert seconds to days (86400s/day)"
    );
}

#[test]
fn wrapper_uses_atomic_tempfile_rename() {
    assert!(WRAPPER.contains("mktemp"));
    assert!(WRAPPER.contains("mv -f"));
}

#[test]
fn wrapper_emits_failure_sentinel() {
    assert!(WRAPPER.contains("selfdef_package_state_textfile_emit_failed"));
}

#[test]
fn wrapper_emits_all_canonical_gauges() {
    for required in [
        "selfdef_package_manager_apt",
        "selfdef_dpkg_packages_total",
        "selfdef_dpkg_broken_packages",
        "selfdef_apt_pending_total",
        "selfdef_apt_pending_security",
        "selfdef_apt_last_update_unix",
        "selfdef_apt_update_age_days",
        "selfdef_package_state_last_run_unix",
        "selfdef_package_state_textfile_emit_failed",
    ] {
        assert!(
            WRAPPER.contains(required),
            "wrapper must emit gauge {required}"
        );
    }
}

#[test]
fn wrapper_documents_pairing_with_sshd_config() {
    assert!(
        WRAPPER.contains("sshd-config") || WRAPPER.contains("sshd_config"),
        "wrapper docstring should reference sshd-config pairing"
    );
}
