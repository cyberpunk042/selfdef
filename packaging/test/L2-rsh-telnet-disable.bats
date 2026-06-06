#!/usr/bin/env bats
# L2 functional suite for rsh-telnet-disable.
#
# rsh-telnet-disable stops + disables the legacy-cleartext-protocol
# daemons: telnet, rsh, rlogin, rexec, tftp, atftpd, finger.
# Every one of these transmits credentials + commands in cleartext
# (or trivially-cracked obfuscation) over the network. On a
# modern system they should be uninstalled entirely; if installed,
# this module ensures they're at minimum disabled + masked.
#
# Acts on 14 candidate units. Profiles: stop | mask.
#
# Run with: bats packaging/test/L2-rsh-telnet-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/rsh-telnet-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
case "$1" in
    list-unit-files)
        case "$2" in
            telnet.socket|telnetd.service|telnet.service|rsh.socket|rlogin.socket|rexec.socket|rsh.service|rlogin.service|rexec.service|tftp.socket|tftp.service|atftpd.service|finger.socket|finger.service)
                if [[ "${LEGACY_PRESENT:-0}" == "1" ]]; then
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
    CONF="${TMP}/rsh-telnet-disable.toml"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_LEGACY_CONFIG="${CONF}" \
    LEGACY_PRESENT="${LEGACY_PRESENT:-0}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_LEGACY_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_LEGACY_CONFIG="${SELFDEF_LEGACY_CONFIG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_LEGACY_CONFIG="${CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be mask|stop"* ]]
}

@test "no legacy units present → no-op (the healthy default)" {
    write_config "mask"
    LEGACY_PRESENT=0 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "legacy units present + mask profile → masks ALL 14 units" {
    write_config "mask"
    LEGACY_PRESENT=1 run_wd
    for unit in telnet.socket telnetd.service telnet.service \
                rsh.socket rlogin.socket rexec.socket \
                rsh.service rlogin.service rexec.service \
                tftp.socket tftp.service atftpd.service \
                finger.socket finger.service; do
        grep -q "systemctl mask ${unit}" "${SYSEOF_LOG}"
    done
}

@test "legacy units present + stop profile → stop + disable, NO mask" {
    write_config "stop"
    LEGACY_PRESENT=1 run_wd
    grep -q 'systemctl stop telnet.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl disable telnetd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl stop finger.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask' "${SYSEOF_LOG}"
}

@test "DRY_RUN=1 + legacy units present → no systemctl mutation" {
    write_config "mask"
    LEGACY_PRESENT=1 DRY_RUN=1 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "default profile is mask (no profile key)" {
    : > "${CONF}"
    LEGACY_PRESENT=1 run_wd
    grep -q 'systemctl mask telnet.socket' "${SYSEOF_LOG}"
}
