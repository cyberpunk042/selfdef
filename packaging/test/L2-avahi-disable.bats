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

@test "INVARIANT (.socket+.service dual coverage in stop): both units are stopped + disabled (avahi.socket can re-activate .service)" {
    # avahi-daemon.socket can re-activate avahi-daemon.service on
    # demand via systemd socket activation. If only .service is
    # touched, .socket brings it right back. Both must be acted on.
    write_config "stop"
    run_wd
    grep -q 'systemctl stop avahi-daemon.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl disable avahi-daemon.socket' "${SYSEOF_LOG}"
}

@test "INVARIANT (.socket+.service dual coverage in mask): both units are masked" {
    write_config "mask"
    run_wd
    grep -q 'systemctl mask avahi-daemon.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask avahi-daemon.socket' "${SYSEOF_LOG}"
}

@test "INVARIANT (idempotent stop): re-applying stop profile fires the same systemctl set across both applies" {
    write_config "stop"
    run_wd
    first_log="$(cat "${SYSEOF_LOG}")"
    : > "${SYSEOF_LOG}"
    run_wd
    second_log="$(cat "${SYSEOF_LOG}")"
    diff <(printf '%s\n' "${first_log}") <(printf '%s\n' "${second_log}") >/dev/null
}

@test "INVARIANT (idempotent mask): re-applying mask profile fires the same set + does not escalate scope" {
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
    [[ "${output}" == *'"module":"avahi-disable"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=mask'* ]]
}

@test "avahi not present + DRY_RUN=1 → still no mutation (dry-run + detect short-circuit compose correctly)" {
    write_config "mask"
    DRY_RUN=1 AVAHI_PRESENT=0 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "INVARIANT (mask is a superset of stop: stop+disable+mask sequence; stop omits the mask step)" {
    # Lock the architectural contract: mask profile = stop profile
    # + additional mask step. Operator escalation path is
    # stop→mask without re-applying the disable.
    write_config "mask"
    run_wd
    grep -q 'systemctl stop avahi-daemon.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable avahi-daemon.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask avahi-daemon.service' "${SYSEOF_LOG}"
    : > "${SYSEOF_LOG}"
    write_config "stop"
    run_wd
    grep -q 'systemctl stop avahi-daemon.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable avahi-daemon.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask avahi-daemon.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (acted count surfaces in JSON: acted=2 when both units are present — operator dashboard)" {
    write_config "mask"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'acted=2'* ]]
    [[ "${output}" == *'skipped=0'* ]]
}

@test "INVARIANT (acted=0 + no-op message when avahi absent — operator dashboard distinguishes 'applied' vs 'not-present')" {
    write_config "mask"
    output="$(AVAHI_PRESENT=0 run_wd 2>&1)"
    [[ "${output}" == *'no-op'* ]]
    [[ "${output}" == *'avahi not present'* ]]
}

@test "INVARIANT (mask order is stop → disable → mask — NOT mask → stop): mask before stop would leave .service exited but socket-activatable" {
    # The systemctl mask is a runtime-permanent gate; if applied
    # BEFORE stop, the service might already be running. The
    # ordering ensures: stop first (terminate in-flight), disable
    # (clear boot trigger), mask last (permanent gate). Locks the
    # sequence so future refactor doesn't accidentally swap.
    write_config "mask"
    run_wd
    # The log contains the actions in order. Extract them.
    stop_line="$(grep -n 'systemctl stop avahi-daemon.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    disable_line="$(grep -n 'systemctl disable avahi-daemon.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    mask_line="$(grep -n 'systemctl mask avahi-daemon.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    [ "${stop_line}" -lt "${disable_line}" ]
    [ "${disable_line}" -lt "${mask_line}" ]
}
