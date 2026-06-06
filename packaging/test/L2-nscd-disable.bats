#!/usr/bin/env bats
# L2 functional suite for nscd-disable.
#
# nscd-disable stops + disables nscd (the Name Service Cache
# Daemon, part of glibc). nscd has a history of vulnerabilities
# (CVE-2014-0475 + CVE-2022-23218 family) and is largely
# obsoleted by systemd-resolved / sssd / direct nsswitch caching.
# On modern systems it's typically pure attack surface — its
# cache also poisons local name resolution in ways that defeat
# operator forensics.
#
# Acts on 2 units (nscd.service + nscd.socket). Profiles: stop |
# mask. DRY_RUN=1 → no system changes.
#
# Run with: bats packaging/test/L2-nscd-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/nscd-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
case "$1" in
    list-unit-files)
        case "$2" in
            nscd.service|nscd.socket)
                if [[ "${NSCD_PRESENT:-1}" == "1" ]]; then
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
    CONF="${TMP}/nscd-disable.toml"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_NSCD_CONFIG="${CONF}" \
    NSCD_PRESENT="${NSCD_PRESENT:-1}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_NSCD_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_NSCD_CONFIG="${SELFDEF_NSCD_CONFIG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_NSCD_CONFIG="${CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be mask|stop"* ]]
}

@test "nscd not present → no mutation" {
    write_config "mask"
    NSCD_PRESENT=0 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "mask profile acts on BOTH nscd.service + nscd.socket" {
    write_config "mask"
    run_wd
    grep -q 'systemctl mask nscd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask nscd.socket' "${SYSEOF_LOG}"
}

@test "stop profile acts on both (stop + disable, NO mask)" {
    write_config "stop"
    run_wd
    grep -q 'systemctl stop nscd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable nscd.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask' "${SYSEOF_LOG}"
}

@test "DRY_RUN=1 → no systemctl mutation" {
    write_config "mask"
    DRY_RUN=1 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "default profile is mask (no profile key — secure default)" {
    : > "${CONF}"
    run_wd
    grep -q 'systemctl mask nscd.service' "${SYSEOF_LOG}"
}
