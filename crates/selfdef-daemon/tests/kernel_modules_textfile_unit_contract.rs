//! selfdef-kernel-modules-textfile observer — contract test.
//!
//! Locks the 12th sibling textfile observer shipped this commit.
//! Surfaces loaded kernel module state for post-exploitation
//! rootkit detection + tainted-kernel monitoring.

const SERVICE_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-kernel-modules-textfile.service");
const TIMER_UNIT: &str =
    include_str!("../../../packaging/systemd/selfdef-kernel-modules-textfile.timer");
const WRAPPER: &str = include_str!("../../../packaging/scripts/selfdef-kernel-modules-textfile.sh");

#[test]
fn service_invokes_the_wrapper_at_canonical_path() {
    assert!(
        SERVICE_UNIT.contains("ExecStart=/usr/share/selfdef/selfdef-kernel-modules-textfile.sh")
    );
}

#[test]
fn service_writes_to_node_exporter_textfile_collector_dir() {
    assert!(SERVICE_UNIT.contains(
        "SELFDEF_KERNEL_MODULES_TEXTFILE_PATH=/var/lib/node_exporter/textfile_collector/selfdef-kernel-modules.prom"
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
            "missing hardening clause: {required}"
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
fn timer_has_360s_offset_boot_delay() {
    // 12th sibling timer.
    assert!(
        TIMER_UNIT.contains("OnBootSec=360s"),
        "timer must have 360s offset (12th distinct above 11 siblings)"
    );
}

#[test]
fn timer_binds_to_the_service() {
    assert!(TIMER_UNIT.contains("Unit=selfdef-kernel-modules-textfile.service"));
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
fn wrapper_reads_proc_modules() {
    assert!(
        WRAPPER.contains("/proc/modules"),
        "wrapper must read /proc/modules"
    );
}

#[test]
fn wrapper_reads_proc_sys_kernel_tainted() {
    assert!(
        WRAPPER.contains("/proc/sys/kernel/tainted"),
        "wrapper must read kernel tainted bitmask"
    );
}

#[test]
fn wrapper_uses_atomic_tempfile_rename() {
    assert!(WRAPPER.contains("mktemp"));
    assert!(WRAPPER.contains("mv -f"));
}

#[test]
fn wrapper_emits_failure_sentinel() {
    assert!(WRAPPER.contains("selfdef_kernel_modules_textfile_emit_failed"));
}

#[test]
fn wrapper_emits_all_canonical_gauges() {
    for required in [
        "selfdef_kernel_modules_total",
        "selfdef_kernel_modules_in_use",
        "selfdef_kernel_tainted",
        "selfdef_kernel_tainted_proprietary",
        "selfdef_kernel_tainted_unsigned",
        "selfdef_kernel_tainted_out_of_tree",
        "selfdef_kernel_modules_last_run_unix",
        "selfdef_kernel_modules_textfile_emit_failed",
    ] {
        assert!(
            WRAPPER.contains(required),
            "wrapper must emit gauge {required}"
        );
    }
}

#[test]
fn wrapper_decodes_tainted_bitmask_correctly() {
    // The 3 canonical taint bits the wrapper extracts:
    //   bit 0  (1)    = proprietary
    //   bit 12 (4096) = unsigned (IPS hazard)
    //   bit 14 (16384) = out-of-tree
    for bit in ["& 1 ))", "& 4096 ))", "& 16384 ))"] {
        assert!(
            WRAPPER.contains(bit),
            "wrapper must check tainted bit {bit}"
        );
    }
}

#[test]
fn wrapper_in_use_count_filters_instances() {
    // in_use_modules counts entries where instances ($3) > 0.
    assert!(
        WRAPPER.contains("$3 > 0"),
        "wrapper must filter in-use modules on instances > 0"
    );
}

#[test]
fn wrapper_documents_rootkit_detection_purpose() {
    assert!(
        WRAPPER.contains("rootkit"),
        "wrapper docstring must explain rootkit detection purpose"
    );
}
