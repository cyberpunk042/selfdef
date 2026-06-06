#!/usr/bin/env bats
# L2 functional suite for avahi-disable.
#
# avahi-disable stops + disables Avahi (mDNS/DNS-SD daemon).
# Avahi advertises the host's services on the local network — every
# enabled service is a fingerprint + lateral-movement target. On a
# sovereign endpoint with no need to advertise (server, workstation),
# Avahi is pure attack surface.
#
# Acts on TWO units (avahi-daemon.service + avahi-daemon.socket) per
# the AVAHI_UNITS array in lib.sh. Profiles: stop | mask. DRY_RUN=1
# → no system changes.
#
# Tests shadow systemctl on PATH with a deterministic fake that
# logs every invocation. Uses the same pattern as L2-at-disable.bats
# (the first installer-module L2 suite).
#
# Run with: bats packaging/test/L2-avahi-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
case "$1" in
    list-unit-files)
        case "$2" in
            avahi-daemon.service|avahi-daemon.socket)
                if [[ "${AVAHI_PRESENT:-1}" == "1" ]]; then
                    printf 'UNIT FILE     STATE\n%s   enabled\n' "$2"
                    exit 0
                else
                    exit 1
                fi ;;
        esac ;;
    is-active|is-enabled)
        exit 0 ;;
esac
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/avahi-disable.toml"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_AVAHI_CONFIG="${CONF}" \
    AVAHI_PRESENT="${AVAHI_PRESENT:-1}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_AVAHI_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_AVAHI_CONFIG="${SELFDEF_AVAHI_CONFIG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile value → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_AVAHI_CONFIG="${CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be mask|stop"* ]]
}

@test "avahi not present → ok no-op, no stop/disable/mask" {
    write_config "mask"
    AVAHI_PRESENT=0 run_wd
    # Only list-unit-files runs (twice, once per AVAHI_UNITS entry).
    [ "$(grep -c 'systemctl list-unit-files' "${SYSEOF_LOG}")" -eq 2 ]
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "DRY_RUN=1 → no systemctl mutation" {
    write_config "mask"
    DRY_RUN=1 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "stop profile (real) → stop + disable both units, NO mask" {
    write_config "stop"
    run_wd
    grep -q 'systemctl stop avahi-daemon.service' "${SYSEOF_LOG}"
    grep -q 'systemctl stop avahi-daemon.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl disable avahi-daemon.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable avahi-daemon.socket' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask' "${SYSEOF_LOG}"
}

@test "mask profile (real) → stop + disable + mask both units" {
    write_config "mask"
    run_wd
    grep -q 'systemctl mask avahi-daemon.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask avahi-daemon.socket' "${SYSEOF_LOG}"
}

@test "default profile is mask (when config has no profile key)" {
    : > "${CONF}"
    run_wd
    grep -q 'systemctl mask avahi-daemon.service' "${SYSEOF_LOG}"
}

@test "idempotent on second run" {
    write_config "mask"
    run_wd
    : > "${SYSEOF_LOG}"
    run_wd
    # systemctl invocations replay; the units stay in the disabled
    # state. Real systemctl is idempotent and our fake always exits 0.
    grep -q 'systemctl mask avahi-daemon.service' "${SYSEOF_LOG}"
}
