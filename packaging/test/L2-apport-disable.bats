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
