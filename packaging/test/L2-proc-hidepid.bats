#!/usr/bin/env bats
# L2 functional suite for proc-hidepid.
#
# proc-hidepid installs a systemd .mount unit that re-mounts
# /proc with hidepid= option, hiding /proc/<pid> entries from
# users who don't own those processes. Blocks the
# enumeration-then-attack pattern (an attacker reading other
# users' /proc/<pid>/cmdline, /proc/<pid>/environ, etc. to find
# secrets like API tokens in process args + env).
#
# Profiles:
#   noaccess  → hidepid=2 (entries exist but content hidden)
#   invisible → hidepid=4 (entries don't even exist in readdir)
#
# CRITICAL INVARIANTS:
#   - invisible profile REQUIRES acknowledge_hidepid=true (refuse-
#     to-brick — invisible breaks dbus + monitoring daemons).
#   - Optional bypass_gid in config adds gid=<n> to mount opts
#     (operator-pull for monitoring groups).
#   - Idempotent: byte-identical re-install fires NO daemon-
#     reload (fixed 2026-06-06 — same lesson as dns-shield).
#
# Uses SELFDEF_SYSTEMD_DIR env-var (already present) for L2
# testability.
#
# Run with: bats packaging/test/L2-proc-hidepid.bats

WD="${BATS_TEST_DIRNAME}/../../modules/proc-hidepid/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    cat > "${BIN}/mount" <<'MOEOF'
#!/usr/bin/env bash
printf 'mount %s\n' "$*" >> "${MOUNT_LOG}"
exit 0
MOEOF
    chmod +x "${BIN}/mount"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    export MOUNT_LOG="${TMP}/mount.log"
    : > "${SYSEOF_LOG}"
    : > "${MOUNT_LOG}"
    CONF="${TMP}/proc-hidepid.toml"
    SYSTEMD_DIR="${TMP}/systemd"
    mkdir -p "${SYSTEMD_DIR}"
}

teardown() { rm -rf "${TMP}"; }

# write_config <profile> [acknowledge_hidepid] [bypass_gid]
write_config() {
    local profile="$1" ack="${2:-false}" gid="${3:-}"
    {
        printf 'profile = "%s"\n' "${profile}"
        printf 'acknowledge_hidepid = %s\n' "${ack}"
        if [[ -n "${gid}" ]]; then
            printf 'bypass_gid = "%s"\n' "${gid}"
        fi
    } > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    MOUNT_LOG="${MOUNT_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_PROC_HIDEPID_CONFIG="${CONF}" \
    SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_PROC_HIDEPID_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_PROC_HIDEPID_CONFIG="${SELFDEF_PROC_HIDEPID_CONFIG}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_PROC_HIDEPID_CONFIG="${CONF}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be noaccess|invisible"* ]]
}

@test "INVARIANT: invisible profile without ack → die (refuse-to-brick)" {
    write_config "invisible" "false"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_PROC_HIDEPID_CONFIG="${CONF}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"can break dbus + monitoring daemons"* ]]
    # Mount unit MUST NOT be installed.
    ! [ -f "${SYSTEMD_DIR}/proc.mount" ]
}

@test "noaccess profile installs mount unit with hidepid=2" {
    write_config "noaccess"
    run_wd
    [ -f "${SYSTEMD_DIR}/proc.mount" ]
    grep -q 'hidepid=2' "${SYSTEMD_DIR}/proc.mount"
    grep -q 'Options=nosuid,nodev,noexec,hidepid=2' "${SYSTEMD_DIR}/proc.mount"
}

@test "invisible profile WITH ack installs mount unit with hidepid=4" {
    write_config "invisible" "true"
    run_wd
    [ -f "${SYSTEMD_DIR}/proc.mount" ]
    grep -q 'hidepid=4' "${SYSTEMD_DIR}/proc.mount"
}

@test "bypass_gid adds gid=<n> to mount options (operator-pull for monitoring groups)" {
    write_config "invisible" "true" "987"
    run_wd
    grep -q 'gid=987' "${SYSTEMD_DIR}/proc.mount"
}

@test "INVARIANT: idempotent — byte-identical re-install fires NO daemon-reload (timestamp removed 2026-06-06)" {
    write_config "noaccess"
    run_wd
    : > "${SYSEOF_LOG}"
    run_wd
    # No daemon-reload = no remount/restart on no-content-change.
    ! grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT: profile change noaccess → invisible (with ack) updates mount + fires daemon-reload" {
    write_config "noaccess"
    run_wd
    write_config "invisible" "true"
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'hidepid=4' "${SYSTEMD_DIR}/proc.mount"
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT: DRY_RUN does not write mount unit or fire daemon-reload" {
    write_config "noaccess"
    DRY_RUN=1 run_wd
    ! [ -f "${SYSTEMD_DIR}/proc.mount" ]
    ! grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "default profile is noaccess (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${SYSTEMD_DIR}/proc.mount" ]
    grep -q 'hidepid=2' "${SYSTEMD_DIR}/proc.mount"
}
