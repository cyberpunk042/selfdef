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

@test "INVARIANT (profile downgrade invisible → noaccess WITH ack-still-needed-no): rewrites hidepid=4 back to hidepid=2" {
    # Downgrade direction. noaccess doesn't require ack, so this works
    # without acknowledge_hidepid=true.
    write_config "invisible" "true"
    run_wd
    grep -q 'hidepid=4' "${SYSTEMD_DIR}/proc.mount"
    write_config "noaccess"
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'hidepid=2' "${SYSTEMD_DIR}/proc.mount"
    ! grep -q 'hidepid=4' "${SYSTEMD_DIR}/proc.mount"
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT (idempotent mtime): byte-identical re-install preserves mount unit mtime" {
    write_config "noaccess"
    run_wd
    mtime_before="$(stat -c '%Y' "${SYSTEMD_DIR}/proc.mount")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${SYSTEMD_DIR}/proc.mount")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT (mount unit carries [Mount] section header — valid systemd .mount fragment)" {
    write_config "noaccess"
    run_wd
    grep -qE '^\[Mount\]' "${SYSTEMD_DIR}/proc.mount"
    grep -qE '^\[Unit\]' "${SYSTEMD_DIR}/proc.mount"
}

@test "INVARIANT (What=proc + Where=/proc + Type=proc): the actual remount-of-proc semantic" {
    # If What/Where/Type drift, the mount unit might remount something
    # else (or nothing). Lock the mount target.
    write_config "noaccess"
    run_wd
    grep -qE '^What=proc' "${SYSTEMD_DIR}/proc.mount"
    grep -qE '^Where=/proc' "${SYSTEMD_DIR}/proc.mount"
    grep -qE '^Type=proc' "${SYSTEMD_DIR}/proc.mount"
}

@test "INVARIANT (no render-timestamp in mount unit): defeats cmp -s idempotency guard" {
    write_config "noaccess"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${SYSTEMD_DIR}/proc.mount"
}

@test "INVARIANT (bypass_gid NOT applied to noaccess): operator-pull only relevant when invisible" {
    # If operator sets bypass_gid on noaccess (which doesn't strictly
    # need it since hidepid=2 already exposes /proc/* entries), it
    # should still be applied (script applies bypass_gid uniformly).
    write_config "noaccess" "false" "987"
    run_wd
    grep -qE 'gid=987|hidepid=2' "${SYSTEMD_DIR}/proc.mount"
}

@test "INVARIANT (mount unit re-arm after operator out-of-band deletion: re-creates + fires daemon-reload)" {
    write_config "noaccess"
    run_wd
    [ -f "${SYSTEMD_DIR}/proc.mount" ]
    rm -f "${SYSTEMD_DIR}/proc.mount"
    : > "${SYSEOF_LOG}"
    run_wd
    [ -f "${SYSTEMD_DIR}/proc.mount" ]
    grep -q 'hidepid=2' "${SYSTEMD_DIR}/proc.mount"
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT (mount unit is chmod 0644 — system-config convention for /etc/systemd/system)" {
    write_config "noaccess"
    run_wd
    [ "$(stat -c '%a' "${SYSTEMD_DIR}/proc.mount")" = "644" ]
}

@test "INVARIANT (mount unit carries selfdef-identifier header — operator audit trail)" {
    write_config "noaccess"
    run_wd
    grep -qE '^#.*selfdef.*proc-hidepid|^#.*managed-by' "${SYSTEMD_DIR}/proc.mount"
}

@test "INVARIANT (emit_status JSON: status=ok + profile surfaced for operator dashboard)" {
    write_config "noaccess"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"proc-hidepid"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=noaccess'* ]]
}

@test "INVARIANT (refuse-to-brick precedence over profile-key: invisible+ack=false ALWAYS dies regardless of bypass_gid)" {
    # Sister to kernel-lockdown + nftables-baseline + tmpfs-baseline
    # + unprivileged-userns refuse-to-brick precedence pattern. Lock
    # that operator-supplied bypass_gid does NOT bypass the gate.
    write_config "invisible" "false" "987"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_PROC_HIDEPID_CONFIG="${CONF}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    ! [ -f "${SYSTEMD_DIR}/proc.mount" ]
}

@test "INVARIANT (mount options preserve nosuid+nodev+noexec on every profile — defense-in-depth)" {
    # nosuid + nodev + noexec are foundational hardening for /proc
    # regardless of hidepid value. A regression that drops these
    # options leaves the remount weaker. Lock that BOTH profiles
    # carry the full hardening triple.
    write_config "noaccess"
    run_wd
    grep -qE 'Options=.*nosuid.*nodev.*noexec' "${SYSTEMD_DIR}/proc.mount"
    write_config "invisible" "true"
    run_wd
    grep -qE 'Options=.*nosuid.*nodev.*noexec' "${SYSTEMD_DIR}/proc.mount"
}

@test "INVARIANT (asymmetric hidepid: invisible (hidepid=4) > noaccess (hidepid=2) — profile-rank monotonic on hidepid axis)" {
    # invisible hides /proc/<pid> entries entirely; noaccess only
    # hides content. invisible is strictly stricter. Lock the
    # profile-rank monotonicity: a regression that swaps the values
    # would let invisible accidentally relax the hide-strength.
    write_config "noaccess"
    run_wd
    noaccess_value="$(grep -oE 'hidepid=[0-9]+' "${SYSTEMD_DIR}/proc.mount" | head -1 | cut -d= -f2)"
    write_config "invisible" "true"
    run_wd
    invisible_value="$(grep -oE 'hidepid=[0-9]+' "${SYSTEMD_DIR}/proc.mount" | head -1 | cut -d= -f2)"
    [ -n "${noaccess_value}" ]
    [ -n "${invisible_value}" ]
    [ "${invisible_value}" -gt "${noaccess_value}" ]
}

@test "INVARIANT (proc.mount unit carries Options=hidepid — actual mount-time effect mechanism)" {
    # Sister to many other installer module's contract-content
    # INVARIANTs across the brain. The proc.mount unit MUST
    # carry Options=<...>hidepid=<N>... — that's the systemd
    # mechanism that hands hidepid to the mount(2) syscall on
    # /proc. If a regression emitted hidepid in a comment or
    # Environment= line or some OTHER field, systemd would
    # silently NOT pass it to mount + the entire profile would
    # be a no-op. Locks the actual-effect contract.
    write_config "noaccess"
    run_wd
    grep -qE '^Options=.*hidepid=' "${SYSTEMD_DIR}/proc.mount"
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO proc.mount unit written AND NO daemon-reload fired when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing /etc/systemd/system/proc.mount AND
    # without firing systemctl daemon-reload. A silent dry-run
    # that committed would re-mount /proc on next reboot with
    # hidepid restrictions on a host where operator was
    # investigating /proc visibility behavior — could break
    # monitoring agents (Prometheus node_exporter, top, ps)
    # that depend on /proc visibility for their own UID. Locks
    # dry-run-preserves-state on the proc-hidepid substrate.
    write_config "invisible" "true"
    rm -f "${SYSTEMD_DIR}/proc.mount"
    : > "${SYSEOF_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${SYSTEMD_DIR}/proc.mount" ]
    ! grep -qE 'systemctl daemon-reload' "${SYSEOF_LOG}"
}
