#!/usr/bin/env bats
# L2 functional suite for ctrlaltdel-disable.
#
# ctrlaltdel-disable blocks the Ctrl+Alt+Del reboot vector. Two
# profiles:
#   mask         → systemctl mask ctrl-alt-del.target (the unit
#                  systemd maps the chord to; masking blocks ALL
#                  presses)
#   burst-guard  → write logind drop-in with CtrlAltDelBurstAction=
#                  none (allows single press = normal reboot but
#                  blocks the 7-press-in-2s emergency hard-reset)
#
# Physical Ctrl+Alt+Del is the universal "fast-path-to-reboot"
# vector. An attacker with physical access (or a janitor with a
# USB Rubber Ducky) can use it to bypass an interactive session
# lock + initiate reboot to a malicious USB / network boot. Mask
# closes the door entirely.
#
# Uses SELFDEF_LOGIND_DROPIN_DIR env-var override (already present
# in the script) for L2 testability without writing to the real
# /etc/systemd/logind.conf.d.
#
# Run with: bats packaging/test/L2-ctrlaltdel-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/ctrlaltdel-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/ctrlaltdel-disable.toml"
    LOGIND_DIR="${TMP}/logind.conf.d"
    LOGIND_DROPIN="${LOGIND_DIR}/50-selfdef-cad.conf"
    # Both SELFDEF_LOGIND_DROPIN_DIR (for mkdir -p) and
    # SELFDEF_LOGIND_DROPIN (for the write target) are now
    # overridable — the lib.sh override was added 2026-06-06 so the
    # burst-guard idempotency invariant can be exercised in tests.
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_CAD_CONFIG="${CONF}" \
    SELFDEF_LOGIND_DROPIN_DIR="${LOGIND_DIR}" \
    SELFDEF_LOGIND_DROPIN="${LOGIND_DROPIN}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_CAD_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_CAD_CONFIG="${SELFDEF_CAD_CONFIG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile value → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_CAD_CONFIG="${CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be mask|burst-guard"* ]]
}

@test "mask profile → systemctl mask ctrl-alt-del.target" {
    write_config "mask"
    run_wd
    grep -q 'systemctl mask ctrl-alt-del.target' "${SYSEOF_LOG}"
}

@test "DRY_RUN=1 + mask profile → no systemctl mutation" {
    write_config "mask"
    DRY_RUN=1 run_wd
    ! grep -q 'systemctl mask' "${SYSEOF_LOG}"
}

@test "DRY_RUN=1 + burst-guard profile → no file written, no systemctl reload" {
    write_config "burst-guard"
    DRY_RUN=1 run_wd
    # The dropin file MUST NOT exist after DRY_RUN.
    ! [ -f /etc/systemd/logind.conf.d/50-selfdef-cad.conf ]
    # systemctl reload also doesn't fire.
    ! grep -q 'systemctl kill -s HUP systemd-logind' "${SYSEOF_LOG}"
}

@test "default profile is mask (no profile key)" {
    : > "${CONF}"
    run_wd
    grep -q 'systemctl mask ctrl-alt-del.target' "${SYSEOF_LOG}"
}

@test "mask profile is idempotent on second run" {
    write_config "mask"
    run_wd
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'systemctl mask ctrl-alt-del.target' "${SYSEOF_LOG}"
}

@test "INVARIANT: burst-guard idempotent — re-install does NOT rewrite logind drop-in OR fire logind reload (2026-06-06 idempotency fix)" {
    write_config "burst-guard"
    run_wd
    [ -f "${LOGIND_DROPIN}" ]
    mtime_before="$(stat -c '%Y' "${LOGIND_DROPIN}")"
    : > "${SYSEOF_LOG}"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${LOGIND_DROPIN}")"
    [ "${mtime_before}" = "${mtime_after}" ]
    # Reload-side-effect gated on content-change.
    ! grep -q 'systemctl kill -s HUP systemd-logind' "${SYSEOF_LOG}"
}

@test "INVARIANT: no render-timestamp in logind drop-in (defeats cmp -s)" {
    write_config "burst-guard"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "${LOGIND_DROPIN}"
}

@test "INVARIANT (burst-guard profile content): logind drop-in carries CtrlAltDelBurstAction=none" {
    write_config "burst-guard"
    run_wd
    grep -qE '^CtrlAltDelBurstAction=none' "${LOGIND_DROPIN}"
}

@test "INVARIANT (burst-guard profile installs drop-in + fires logind reload first time)" {
    write_config "burst-guard"
    run_wd
    [ -f "${LOGIND_DROPIN}" ]
    grep -q 'systemctl kill -s HUP systemd-logind' "${SYSEOF_LOG}"
}

@test "INVARIANT (profile change mask → burst-guard): writes drop-in + reloads logind on transition" {
    write_config "mask"
    run_wd
    write_config "burst-guard"
    : > "${SYSEOF_LOG}"
    run_wd
    [ -f "${LOGIND_DROPIN}" ]
    grep -q 'systemctl kill -s HUP systemd-logind' "${SYSEOF_LOG}"
}

@test "INVARIANT (logind drop-in perms): drop-in is chmod 0644 (system-config convention for /etc/systemd/logind.conf.d)" {
    write_config "burst-guard"
    run_wd
    [ "$(stat -c '%a' "${LOGIND_DROPIN}")" = "644" ]
}

@test "INVARIANT (logind drop-in carries [Login] section header): valid logind.conf.d fragment shape" {
    write_config "burst-guard"
    run_wd
    grep -qE '^\[Login\]' "${LOGIND_DROPIN}"
}

@test "INVARIANT (mask profile does NOT write logind drop-in — the two profiles are mutually-exclusive mechanisms)" {
    # mask blocks ALL Ctrl+Alt+Del presses via target masking;
    # burst-guard allows single press + blocks 7-press burst via
    # logind drop-in. These are different mechanisms, never
    # composed. Lock that mask doesn't accidentally write the
    # drop-in too.
    write_config "mask"
    run_wd
    ! [ -f "${LOGIND_DROPIN}" ]
    grep -q 'systemctl mask ctrl-alt-del.target' "${SYSEOF_LOG}"
    ! grep -q 'systemctl kill -s HUP systemd-logind' "${SYSEOF_LOG}"
}

@test "INVARIANT (logind drop-in carries managed-by header marker — operator audit trail)" {
    # Header marker enables stale-cleanup head -1 grep for
    # ownership identification. Operator audit trail too —
    # 'who put this drop-in here'.
    write_config "burst-guard"
    run_wd
    grep -qE '^#.*selfdef.*ctrlaltdel|^#.*managed-by.*selfdef' "${LOGIND_DROPIN}"
}

@test "INVARIANT (burst-guard re-arm after operator deletion: re-creates drop-in + fires logind reload)" {
    # Operator deletes the drop-in out-of-band. Next apply re-
    # creates with intact content + fires logind reload to apply
    # live.
    write_config "burst-guard"
    run_wd
    [ -f "${LOGIND_DROPIN}" ]
    rm -f "${LOGIND_DROPIN}"
    : > "${SYSEOF_LOG}"
    run_wd
    [ -f "${LOGIND_DROPIN}" ]
    grep -qE '^CtrlAltDelBurstAction=none' "${LOGIND_DROPIN}"
    grep -q 'systemctl kill -s HUP systemd-logind' "${SYSEOF_LOG}"
}

@test "INVARIANT (emit_status JSON: status=ok + profile surfaced for operator dashboard)" {
    write_config "mask"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"ctrlaltdel-disable"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=mask'* ]]
}
