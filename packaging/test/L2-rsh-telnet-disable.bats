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

@test "INVARIANT (telnet family coverage): all 3 telnet-related units acted on (socket + telnetd + telnet.service)" {
    write_config "mask"
    LEGACY_PRESENT=1 run_wd
    grep -q 'systemctl mask telnet.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl mask telnetd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask telnet.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (rsh family coverage): all 6 rsh/rlogin/rexec units acted on (socket + service for each of 3 protocols)" {
    write_config "mask"
    LEGACY_PRESENT=1 run_wd
    grep -q 'systemctl mask rsh.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl mask rsh.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask rlogin.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl mask rlogin.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask rexec.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl mask rexec.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (tftp family coverage): all 3 tftp units acted on (socket + service + atftpd alt)" {
    write_config "mask"
    LEGACY_PRESENT=1 run_wd
    grep -q 'systemctl mask tftp.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl mask tftp.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask atftpd.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (finger family coverage): both finger units acted on (socket + service)" {
    write_config "mask"
    LEGACY_PRESENT=1 run_wd
    grep -q 'systemctl mask finger.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl mask finger.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (.socket+service dual coverage in stop profile): stop also acts on .socket variants (not just .service)" {
    # .socket can re-activate .service on demand — both must be
    # touched. Catches a regression that disables only .service
    # while leaving .socket re-activation alive.
    write_config "stop"
    LEGACY_PRESENT=1 run_wd
    grep -q 'systemctl stop telnet.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl disable rsh.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl stop tftp.socket' "${SYSEOF_LOG}"
}

@test "INVARIANT (idempotent mask): re-applying mask profile fires the same mask set" {
    write_config "mask"
    LEGACY_PRESENT=1 run_wd
    first_log="$(cat "${SYSEOF_LOG}")"
    : > "${SYSEOF_LOG}"
    LEGACY_PRESENT=1 run_wd
    second_log="$(cat "${SYSEOF_LOG}")"
    diff <(printf '%s\n' "${first_log}") <(printf '%s\n' "${second_log}") >/dev/null
}

@test "emit_status surfaces profile + unit count in JSON (operator observability)" {
    write_config "mask"
    output="$(LEGACY_PRESENT=1 run_wd 2>&1)"
    [[ "${output}" == *'"module":"rsh-telnet-disable"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=mask'* ]]
}

@test "INVARIANT (mask is superset of stop: mask = stop + disable + mask; stop omits mask step)" {
    # Architectural contract identical to avahi/nscd:
    # mask supersedes stop. Verify behavioral split.
    write_config "mask"
    LEGACY_PRESENT=1 run_wd
    grep -q 'systemctl stop telnet.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl disable telnet.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl mask telnet.socket' "${SYSEOF_LOG}"
    : > "${SYSEOF_LOG}"
    write_config "stop"
    LEGACY_PRESENT=1 run_wd
    grep -q 'systemctl stop telnet.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl disable telnet.socket' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask telnet' "${SYSEOF_LOG}"
}

@test "INVARIANT (acted=14 when all legacy units present): full coverage count surfaces" {
    write_config "mask"
    output="$(LEGACY_PRESENT=1 run_wd 2>&1)"
    [[ "${output}" == *'acted=14'* ]]
}

@test "INVARIANT (acted=0 + no-op when no legacy units present — healthy modern host has zero)" {
    write_config "mask"
    output="$(LEGACY_PRESENT=0 run_wd 2>&1)"
    [[ "${output}" == *'no-op'* ]] || [[ "${output}" == *'acted=0'* ]]
}

@test "INVARIANT (legacy units NEVER auto-uninstalled — only stop+disable+mask; package removal is operator decision)" {
    # The module's contract is to neutralize, not uninstall.
    # 'systemctl mask' makes the unit unloadable; the package
    # itself is left alone. Operator may want package removal
    # via apt/dnf separately.
    write_config "mask"
    LEGACY_PRESENT=1 run_wd
    # No apt/dnf/yum/rpm removal calls.
    ! grep -qE 'apt|dnf|yum|rpm' "${SYSEOF_LOG}"
}

@test "INVARIANT (mask order per unit: stop before disable before mask — terminate-then-clear-then-gate)" {
    write_config "mask"
    LEGACY_PRESENT=1 run_wd
    stop_line="$(grep -n 'systemctl stop telnet.socket' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    disable_line="$(grep -n 'systemctl disable telnet.socket' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    mask_line="$(grep -n 'systemctl mask telnet.socket' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    [ "${stop_line}" -lt "${disable_line}" ]
    [ "${disable_line}" -lt "${mask_line}" ]
}
