#!/usr/bin/env bats
# L2 functional suite for at-disable.
#
# at-disable stops + disables atd.service (the at(1) cron-job
# scheduler). The mask profile additionally `systemctl mask` it so
# a future install / package upgrade can't re-enable it. at(1)
# scheduling is a persistence + privilege-execution surface — an
# attacker who schedules a job via `at` gets delayed execution under
# whichever uid they ran it as (root if from a privileged shell).
#
# Profiles: stop (just stop+disable) | mask (stop+disable+mask).
# DRY_RUN=1 → no system changes, just log what would happen.
#
# Tests shadow systemctl + atq on PATH with deterministic fakes.
#
# Run with: bats packaging/test/L2-at-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/at-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    # Fake systemctl: tracks ALL invocations to a log file. list-unit-files
    # returns success (claims atd.service exists) so apply.sh proceeds past
    # the "atd not installed" no-op branch.
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
case "$1" in
    list-unit-files)
        # Exit 0 if the unit is in our fake-present list.
        case "$2" in
            atd.service)
                if [[ "${ATD_PRESENT:-1}" == "1" ]]; then
                    printf 'UNIT FILE     STATE\natd.service   enabled\n'
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
    cat > "${BIN}/atq" <<'AEOF'
#!/usr/bin/env bash
exit 0       # no pending jobs
AEOF
    chmod +x "${BIN}/atq"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/at-disable.toml"
}

teardown() { rm -rf "${TMP}"; }

# write_config <profile>
write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_AT_DISABLE_CONFIG="${CONF}" \
    ATD_PRESENT="${ATD_PRESENT:-1}" \
    bash "${WD}"
}

@test "missing config → die with non-zero exit" {
    # Config file path doesn't exist.
    SELFDEF_AT_DISABLE_CONFIG="${TMP}/missing-config.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_DRY_RUN=0 \
        SELFDEF_AT_DISABLE_CONFIG="${SELFDEF_AT_DISABLE_CONFIG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile value → die" {
    write_config "exterminate"      # not in {mask, stop}
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_DRY_RUN=0 \
        SELFDEF_AT_DISABLE_CONFIG="${CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be mask|stop"* ]]
}

@test "atd.service not present → ok no-op, no systemctl mutation" {
    write_config "mask"
    ATD_PRESENT=0 run_wd
    # systemctl list-unit-files runs once (the present-check) but no
    # stop/disable/mask invocations.
    grep -qE 'systemctl list-unit-files' "${SYSEOF_LOG}"
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "DRY_RUN=1 + stop profile → no systemctl mutation" {
    write_config "stop"
    DRY_RUN=1 run_wd
    # list-unit-files runs (the present-check), but no stop/disable/mask.
    grep -qE 'systemctl list-unit-files' "${SYSEOF_LOG}"
    ! grep -qE 'systemctl stop atd.service|systemctl disable atd.service|systemctl mask' "${SYSEOF_LOG}"
}

@test "DRY_RUN=1 + mask profile → no systemctl mutation" {
    write_config "mask"
    DRY_RUN=1 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "stop profile (real) → stop + disable, no mask" {
    write_config "stop"
    run_wd
    grep -q 'systemctl stop atd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable atd.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask atd.service' "${SYSEOF_LOG}"
}

@test "mask profile (real) → stop + disable + mask" {
    write_config "mask"
    run_wd
    grep -q 'systemctl stop atd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable atd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask atd.service' "${SYSEOF_LOG}"
}

@test "real-run is idempotent (second run is safe, no error)" {
    write_config "mask"
    run_wd
    : > "${SYSEOF_LOG}"
    run_wd                    # second run on already-stopped/masked unit
    # systemctl stop/disable/mask all run again (idempotent, the unit-already-
    # in-target-state case returns 0 from real systemctl, ours always returns 0).
    grep -q 'systemctl stop atd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask atd.service' "${SYSEOF_LOG}"
}

@test "default profile is mask (when config has no profile key)" {
    : > "${CONF}"             # empty config — toml_get returns "" → default
    run_wd
    grep -q 'systemctl mask atd.service' "${SYSEOF_LOG}"
}
