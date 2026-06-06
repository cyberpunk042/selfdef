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
    # The script writes the dropin at $LOGIND_DROPIN (hardcoded path
    # in lib.sh). We can override only the parent dir via
    # SELFDEF_LOGIND_DROPIN_DIR. But the LOGIND_DROPIN path is
    # /etc/systemd/logind.conf.d/50-selfdef-cad.conf (set in lib.sh
    # AFTER source), so the override only affects the mkdir -p. The
    # actual write target is the hardcoded LOGIND_DROPIN. To make
    # the test work we run the burst-guard profile in DRY_RUN mode
    # (the only mode that doesn't write the hardcoded path).
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
