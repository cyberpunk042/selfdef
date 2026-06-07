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

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite blacklist (2026-06-06 idempotency fix)" {
    write_config "mask"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    mtime_before="$(stat -c '%Y' "${MODPROBE_FILE}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${MODPROBE_FILE}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: no render-timestamp in modprobe blacklist (defeats cmp -s)" {
    write_config "mask"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "${MODPROBE_FILE}"
}

@test "INVARIANT (rfkill block scope = 'wwan' — NOT 'all' or 'wifi'): per-radio scoping for composability with wireless-disable" {
    # rfkill block 'all' would also kill Wi-Fi (the wireless-disable
    # module owns that surface). Lock per-radio scoping so the two
    # modules can be composed independently.
    write_config "rfkill"
    run_wd
    grep -qE 'rfkill block wwan' "${RF_LOG}"
    ! grep -qE 'rfkill block all' "${RF_LOG}"
    ! grep -qE 'rfkill block wifi' "${RF_LOG}"
    ! grep -qE 'rfkill block bluetooth' "${RF_LOG}"
}

@test "INVARIANT (driver-coverage: cdc_ncm + mhi family — full mhi/qmi/mbim/ncm coverage)" {
    # The pre-existing test covers cdc_mbim + qmi_wwan + option + mhi
    # roots. Lock the broader coverage: cdc_ncm (USB Ethernet-class
    # MBIM transport), mhi_net (modem PCIe wrapper), mhi_pci_generic
    # (PCIe variant).
    write_config "mask"
    run_wd
    grep -q '^blacklist cdc_ncm$' "${MODPROBE_FILE}"
    # Either mhi_net or mhi_pci_generic in the family — lock at
    # least one beyond bare 'mhi'.
    grep -qE '^blacklist mhi_(net|pci_generic)$' "${MODPROBE_FILE}"
}

@test "INVARIANT (header-marker is first non-blank line — predictable for stale-cleanup head -1 grep)" {
    # Same discipline as wireless-disable: downgrade-path stale-
    # cleanup uses head -1 + grep -F. Header MUST be first.
    write_config "mask"
    run_wd
    first_line="$(head -1 "${MODPROBE_FILE}")"
    [ "${first_line}" = "# managed-by: selfdef wwan-disable" ]
}

@test "INVARIANT (mask re-arm after operator deletion: re-creates blacklist with header marker)" {
    write_config "mask"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    rm -f "${MODPROBE_FILE}"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    grep -q 'managed-by: selfdef wwan-disable' "${MODPROBE_FILE}"
}

@test "INVARIANT (ModemManager mask is the architectural complement to rfkill — both fire on rfkill profile, not just mask profile)" {
    # ModemManager is the userspace control plane for WWAN modems.
    # rfkill blocks the radio; masking MM blocks the daemon that
    # auto-connects + auto-pulls OTA pushes from carriers. BOTH
    # mechanisms must fire on rfkill profile too — not deferred
    # to mask profile (which is the persistent-kernel-blacklist
    # axis, not the userspace-daemon axis).
    write_config "rfkill"
    run_wd
    grep -q 'rfkill block wwan' "${RF_LOG}"
    grep -q 'systemctl mask ModemManager.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (JSON emit_status: status=ok + profile surfaced)" {
    write_config "rfkill"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=rfkill'* ]]
}

@test "INVARIANT (emit_status: module=wwan-disable surfaces for operator dashboard)" {
    write_config "mask"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"wwan-disable"'* ]]
    [[ "${output}" == *'profile=mask'* ]]
}

@test "INVARIANT (rfkill re-arm on every apply: rfkill block wwan fires even when blacklist file unchanged)" {
    # rfkill state may be cleared at boot or by operator (rfkill unblock).
    # Each apply MUST re-fire rfkill block — live state is not file-backed.
    write_config "mask"
    run_wd
    : > "${RF_LOG}"
    run_wd
    grep -q 'rfkill block wwan' "${RF_LOG}"
}

@test "INVARIANT (architectural triplet completion: rfkill + ModemManager-mask + modprobe-blacklist comprehensive disable)" {
    # mask profile fires ALL three disable mechanisms simultaneously:
    # 1. rfkill block (radio-layer)
    # 2. systemctl mask ModemManager (userspace control plane)
    # 3. modprobe blacklist (kernel module load gate)
    # Triplet completeness lock against regression dropping any one mechanism.
    write_config "mask"
    run_wd
    grep -q 'rfkill block wwan' "${RF_LOG}"
    grep -q 'systemctl mask ModemManager.service' "${SYSEOF_LOG}"
    [ -f "${MODPROBE_FILE}" ]
    grep -qE '^blacklist cdc_mbim$' "${MODPROBE_FILE}"
}
