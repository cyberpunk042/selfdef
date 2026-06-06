#!/usr/bin/env bats
# L2 functional suite for wwan-disable.
#
# wwan-disable blocks the cellular WWAN modem stack: rfkill block
# wwan + mask ModemManager.service + (mask profile) modprobe
# blacklist preventing cdc_mbim / qmi_wwan / cdc_ncm / option /
# mhi drivers from auto-loading on next boot. On an endpoint
# without legitimate cellular use, the WWAN modem is a remote-
# attack surface: provider OTA pushes, Stingray ID-spoofing, even
# baseband CVEs that the operator can't patch.
#
# Profiles:
#   rfkill → runtime block + ModemManager mask only
#   mask   → rfkill + ModemManager mask + persistent kernel-module
#            blacklist
#
# Mirrors the wireless-disable test pattern (rfkill + modprobe
# blacklist with header-marker collateral-damage protection).
#
# Adds SELFDEF_WWAN_MODPROBE_FILE env-var (added 2026-06-06) for
# L2 testability.
#
# Run with: bats packaging/test/L2-wwan-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/rfkill" <<'RFEOF'
#!/usr/bin/env bash
printf 'rfkill %s\n' "$*" >> "${RF_LOG}"
exit 0
RFEOF
    chmod +x "${BIN}/rfkill"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
case "$1" in
    list-unit-files)
        case "$2" in
            ModemManager.service)
                if [[ "${MM_PRESENT:-1}" == "1" ]]; then
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
    export RF_LOG="${TMP}/rfkill.log"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${RF_LOG}"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/wwan-disable.toml"
    MODPROBE_FILE="${TMP}/selfdef-wwan-blacklist.conf"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    RF_LOG="${RF_LOG}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_WWAN_CONFIG="${CONF}" \
    SELFDEF_WWAN_MODPROBE_FILE="${MODPROBE_FILE}" \
    MM_PRESENT="${MM_PRESENT:-1}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_WWAN_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_WWAN_CONFIG="${SELFDEF_WWAN_CONFIG}" \
        SELFDEF_WWAN_MODPROBE_FILE="${MODPROBE_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_WWAN_CONFIG="${CONF}" \
        SELFDEF_WWAN_MODPROBE_FILE="${MODPROBE_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be rfkill|mask"* ]]
}

@test "rfkill profile fires rfkill block wwan + masks ModemManager — NO modprobe blacklist file" {
    write_config "rfkill"
    run_wd
    grep -q 'rfkill block wwan' "${RF_LOG}"
    grep -q 'systemctl mask ModemManager.service' "${SYSEOF_LOG}"
    ! [ -f "${MODPROBE_FILE}" ]
}

@test "mask profile fires rfkill + ModemManager mask AND writes modprobe blacklist" {
    write_config "mask"
    run_wd
    grep -q 'rfkill block wwan' "${RF_LOG}"
    grep -q 'systemctl mask ModemManager.service' "${SYSEOF_LOG}"
    [ -f "${MODPROBE_FILE}" ]
    grep -q 'managed-by: selfdef wwan-disable' "${MODPROBE_FILE}"
}

@test "modprobe blacklist covers WWAN driver stack (cdc_mbim + qmi_wwan + option + mhi family)" {
    write_config "mask"
    run_wd
    grep -q 'blacklist cdc_mbim' "${MODPROBE_FILE}"
    grep -q 'blacklist qmi_wwan' "${MODPROBE_FILE}"
    grep -q 'blacklist option' "${MODPROBE_FILE}"
    grep -q 'blacklist mhi' "${MODPROBE_FILE}"
    # install $m /bin/true secondary protection.
    grep -q 'install cdc_mbim /bin/true' "${MODPROBE_FILE}"
}

@test "INVARIANT: profile downgrade mask → rfkill REMOVES the blacklist file" {
    write_config "mask"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    write_config "rfkill"
    run_wd
    ! [ -f "${MODPROBE_FILE}" ]
}

@test "INVARIANT: non-selfdef-owned blacklist file is LEFT ALONE" {
    write_config "rfkill"
    printf '%s\n' '# managed-by: somebody-else' 'blacklist some-mod' > "${MODPROBE_FILE}"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    grep -q 'somebody-else' "${MODPROBE_FILE}"
}

@test "INVARIANT: DRY_RUN does not fire rfkill, systemctl mask, or write blacklist" {
    write_config "mask"
    DRY_RUN=1 run_wd
    ! [ -f "${MODPROBE_FILE}" ]
    ! grep -q 'rfkill block wwan' "${RF_LOG}"
    ! grep -q 'systemctl mask ModemManager' "${SYSEOF_LOG}"
}

@test "ModemManager not present → no mask invocation on it (skip cleanly)" {
    write_config "rfkill"
    MM_PRESENT=0 run_wd
    # rfkill still fires.
    grep -q 'rfkill block wwan' "${RF_LOG}"
    # But no mask on ModemManager.
    ! grep -q 'systemctl mask ModemManager' "${SYSEOF_LOG}"
}

@test "default profile is rfkill (no profile key — the conservative default)" {
    : > "${CONF}"
    run_wd
    grep -q 'rfkill block wwan' "${RF_LOG}"
    ! [ -f "${MODPROBE_FILE}" ]
}
