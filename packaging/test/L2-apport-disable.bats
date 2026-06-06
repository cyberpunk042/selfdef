#!/usr/bin/env bats
# L2 functional suite for apport-disable.
#
# apport-disable stops + disables Ubuntu's apport (and whoopsie)
# crash-reporting + crash-handler service family — 6 units total
# (apport.service + apport-autoreport.{service,path,timer} +
# whoopsie.{service,path}). Apport phones home, transmits crash
# data that may contain sensitive memory — sovereign endpoints
# don't want that.
#
# Critically, apport hijacks kernel.core_pattern with a pipe to its
# own binary. Simply masking the service is NOT enough — the kernel
# still invokes the now-masked apport binary on every crash. The
# module ALSO resets core_pattern via sysctl -w if it currently
# pipes to apport.
#
# Adds SELFDEF_APPORT_COREPAT_SOURCE env-var (added 2026-06-06) to
# point the core_pattern read at a fixture file for L2 testability.
# Live default behavior unchanged.
#
# Run with: bats packaging/test/L2-apport-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/apport-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
case "$1" in
    list-unit-files)
        case "$2" in
            apport.service|apport-autoreport.service|apport-autoreport.path|apport-autoreport.timer|whoopsie.service|whoopsie.path)
                if [[ "${APPORT_PRESENT:-1}" == "1" ]]; then
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
    cat > "${BIN}/sysctl" <<'SCEOF'
#!/usr/bin/env bash
printf 'sysctl %s\n' "$*" >> "${SCTL_LOG}"
exit 0
SCEOF
    chmod +x "${BIN}/sysctl"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    export SCTL_LOG="${TMP}/sysctl.log"
    : > "${SYSEOF_LOG}"
    : > "${SCTL_LOG}"
    CONF="${TMP}/apport-disable.toml"
    COREPAT="${TMP}/core_pattern"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SCTL_LOG="${SCTL_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_APPORT_CONFIG="${CONF}" \
    SELFDEF_APPORT_COREPAT_SOURCE="${COREPAT}" \
    APPORT_PRESENT="${APPORT_PRESENT:-1}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_APPORT_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_APPORT_CONFIG="${SELFDEF_APPORT_CONFIG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_APPORT_CONFIG="${CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
}

@test "apport not present → no mutation" {
    write_config "mask"
    APPORT_PRESENT=0 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "mask profile acts on all 6 apport+whoopsie units" {
    write_config "mask"
    run_wd
    for unit in apport.service apport-autoreport.service apport-autoreport.path apport-autoreport.timer whoopsie.service whoopsie.path; do
        grep -q "systemctl mask ${unit}" "${SYSEOF_LOG}"
    done
}

@test "core_pattern pipes to apport → resets to 'core' via sysctl" {
    write_config "mask"
    printf '|/usr/share/apport/apport %%p %%s %%c %%P\n' > "${COREPAT}"
    run_wd
    grep -q 'sysctl -w kernel.core_pattern=core' "${SCTL_LOG}"
}

@test "core_pattern is plain (no apport pipe) → NO sysctl reset" {
    write_config "mask"
    printf 'core\n' > "${COREPAT}"
    run_wd
    ! grep -q 'sysctl -w kernel.core_pattern' "${SCTL_LOG}"
}

@test "DRY_RUN + apport-piped core_pattern → no sysctl mutation" {
    write_config "mask"
    printf '|/usr/share/apport/apport %%p\n' > "${COREPAT}"
    DRY_RUN=1 run_wd
    ! grep -q 'sysctl -w' "${SCTL_LOG}"
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "stop profile (real) → stop + disable, NO mask, NO sysctl" {
    write_config "stop"
    printf 'core\n' > "${COREPAT}"
    run_wd
    grep -q 'systemctl stop apport.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable apport.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask' "${SYSEOF_LOG}"
}

@test "default profile is mask (no profile key)" {
    : > "${CONF}"
    run_wd
    grep -q 'systemctl mask apport.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (apport-autoreport coverage): all 3 autoreport units acted on (.service + .path + .timer)" {
    write_config "mask"
    run_wd
    grep -q 'systemctl mask apport-autoreport.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask apport-autoreport.path' "${SYSEOF_LOG}"
    grep -q 'systemctl mask apport-autoreport.timer' "${SYSEOF_LOG}"
}

@test "INVARIANT (whoopsie coverage): both whoopsie units acted on (.service + .path)" {
    write_config "mask"
    run_wd
    grep -q 'systemctl mask whoopsie.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask whoopsie.path' "${SYSEOF_LOG}"
}

@test "INVARIANT (stop+sysctl composition): stop profile + apport-piped core_pattern → stop+disable + ALSO resets core_pattern" {
    # Even in stop profile, the kernel core_pattern reset must
    # fire if it pipes to apport — otherwise the kernel will
    # still call apport on every crash regardless of unit state.
    write_config "stop"
    printf '|/usr/share/apport/apport %%p %%s\n' > "${COREPAT}"
    run_wd
    grep -q 'sysctl -w kernel.core_pattern=core' "${SCTL_LOG}"
    grep -q 'systemctl stop apport.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (idempotent mask): re-applying mask fires the same systemctl set + sysctl reset" {
    write_config "mask"
    printf '|/usr/share/apport/apport %%p\n' > "${COREPAT}"
    run_wd
    first_sys="$(cat "${SYSEOF_LOG}")"
    first_sctl="$(cat "${SCTL_LOG}")"
    : > "${SYSEOF_LOG}"
    : > "${SCTL_LOG}"
    run_wd
    second_sys="$(cat "${SYSEOF_LOG}")"
    second_sctl="$(cat "${SCTL_LOG}")"
    diff <(printf '%s\n' "${first_sys}") <(printf '%s\n' "${second_sys}") >/dev/null
    diff <(printf '%s\n' "${first_sctl}") <(printf '%s\n' "${second_sctl}") >/dev/null
}

@test "INVARIANT (apport-not-present + apport-piped core_pattern): kernel-side reset STILL fires (even if no apport units present)" {
    # If apport.service is masked/uninstalled but core_pattern
    # was set up by an earlier apport install, the kernel reset
    # must still fire — otherwise the kernel keeps trying to call
    # the now-missing apport binary on every crash.
    write_config "mask"
    printf '|/usr/share/apport/apport %%p\n' > "${COREPAT}"
    APPORT_PRESENT=0 run_wd
    grep -q 'sysctl -w kernel.core_pattern=core' "${SCTL_LOG}"
}

@test "emit_status surfaces profile + result in JSON (operator observability)" {
    write_config "mask"
    printf 'core\n' > "${COREPAT}"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"apport-disable"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=mask'* ]]
}
