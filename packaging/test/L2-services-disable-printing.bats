#!/usr/bin/env bats
# L2 functional suite for services-disable-printing.
#
# services-disable-printing stops + disables CUPS + saned (the
# scanner daemon). On a sovereign endpoint that doesn't print or
# scan, these are pure attack surface — CUPS in particular has
# a long history of remote-code-execution CVEs (see the 2024
# CUPS chain). Acts on 7 candidate units.
#
# Profiles: stop | mask. DRY_RUN=1 → no system changes.
#
# Same systemctl-PATH-shadow test pattern as the other *-disable
# modules.
#
# Run with: bats packaging/test/L2-services-disable-printing.bats

WD="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
case "$1" in
    list-unit-files)
        case "$2" in
            cups.service|cups.socket|cups.path|cups-browsed.service|saned.socket|saned.service|printer.target)
                if [[ "${PRINT_PRESENT:-1}" == "1" ]]; then
                    printf 'UNIT FILE     STATE\n%s   enabled\n' "$2"
                    exit 0
                else
                    exit 1
                fi ;;
        esac ;;
esac
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/services-disable-printing.toml"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_PRINTING_CONFIG="${CONF}" \
    PRINT_PRESENT="${PRINT_PRESENT:-1}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_PRINTING_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_PRINTING_CONFIG="${SELFDEF_PRINTING_CONFIG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_PRINTING_CONFIG="${CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be mask|stop"* ]]
}

@test "no print/scan units present → no mutation" {
    write_config "mask"
    PRINT_PRESENT=0 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "DRY_RUN=1 → no systemctl mutation" {
    write_config "mask"
    DRY_RUN=1 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "mask profile acts on all 7 print/scan units (cups + cups-browsed + saned + printer.target)" {
    write_config "mask"
    run_wd
    for unit in cups.service cups.socket cups.path cups-browsed.service saned.socket saned.service printer.target; do
        grep -q "systemctl mask ${unit}" "${SYSEOF_LOG}"
    done
}

@test "stop profile acts on all 7 units (stop + disable, NO mask)" {
    write_config "stop"
    run_wd
    for unit in cups.service cups.socket cups.path cups-browsed.service saned.socket saned.service printer.target; do
        grep -q "systemctl stop ${unit}" "${SYSEOF_LOG}"
        grep -q "systemctl disable ${unit}" "${SYSEOF_LOG}"
    done
    ! grep -q 'systemctl mask' "${SYSEOF_LOG}"
}

@test "default profile is mask (no profile key)" {
    : > "${CONF}"
    run_wd
    grep -q 'systemctl mask cups.service' "${SYSEOF_LOG}"
}

@test "idempotent on second run" {
    write_config "mask"
    run_wd
    : > "${SYSEOF_LOG}"
    run_wd
    # The systemctl invocations replay; the units stay in target state.
    grep -q 'systemctl mask cups.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (cups family coverage): all 4 cups-related units acted on (.service + .socket + .path + cups-browsed)" {
    write_config "mask"
    run_wd
    grep -q 'systemctl mask cups.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask cups.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl mask cups.path' "${SYSEOF_LOG}"
    grep -q 'systemctl mask cups-browsed.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (saned family coverage): both saned units acted on (.service + .socket)" {
    write_config "mask"
    run_wd
    grep -q 'systemctl mask saned.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask saned.socket' "${SYSEOF_LOG}"
}

@test "INVARIANT (printer.target umbrella): printer.target IS in the action set (umbrella unit)" {
    # printer.target is the systemd target that other printer
    # units WantedBy. Masking it short-circuits the printer-stack
    # activation chain entirely.
    write_config "mask"
    run_wd
    grep -q 'systemctl mask printer.target' "${SYSEOF_LOG}"
}

@test "INVARIANT (cups.socket+cups.path dual coverage in stop): stop also acts on socket+path (not just .service)" {
    # cups.socket + cups.path can both re-activate cups.service on
    # demand. Disabling only .service would leave both activation
    # paths alive.
    write_config "stop"
    run_wd
    grep -q 'systemctl stop cups.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl disable cups.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl stop cups.path' "${SYSEOF_LOG}"
    grep -q 'systemctl disable cups.path' "${SYSEOF_LOG}"
}

@test "INVARIANT (idempotent mask): re-applying mask fires the same systemctl set across both applies" {
    write_config "mask"
    run_wd
    first_log="$(cat "${SYSEOF_LOG}")"
    : > "${SYSEOF_LOG}"
    run_wd
    second_log="$(cat "${SYSEOF_LOG}")"
    diff <(printf '%s\n' "${first_log}") <(printf '%s\n' "${second_log}") >/dev/null
}

@test "emit_status surfaces profile + result in JSON (operator observability)" {
    write_config "mask"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"services-disable-printing"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=mask'* ]]
}
