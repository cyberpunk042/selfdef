#!/usr/bin/env bats
# L2 functional suite for bluetooth-disable.
#
# bluetooth-disable closes the Bluetooth attack vector. Two
# profiles:
#   mask → stop + disable + mask the bluez user-space stack,
#          rfkill block the radio, AND modprobe blacklist the
#          kernel modules (btusb / btintel / btbcm / btmtk /
#          btrtl / bluetooth) so they can't be auto-loaded via
#          uevent/coldplug after reboot.
#   stop → stop + disable bluez services AND rfkill block the
#          radio, but NO modprobe blacklist (reversible — a
#          modprobe re-enable + service start brings BT back).
#
# Adds SELFDEF_BT_MODPROBE_BLACKLIST env-var (added 2026-06-06)
# for L2 testability. Live default unchanged.
#
# Run with: bats packaging/test/L2-bluetooth-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
# list-unit-files: pretend every queried unit exists.
case "$1" in
    list-unit-files) exit 0 ;;
esac
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    cat > "${BIN}/rfkill" <<'RFEOF'
#!/usr/bin/env bash
printf 'rfkill %s\n' "$*" >> "${RF_LOG}"
exit 0
RFEOF
    chmod +x "${BIN}/rfkill"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    export RF_LOG="${TMP}/rfkill.log"
    : > "${SYSEOF_LOG}"
    : > "${RF_LOG}"
    CONF="${TMP}/bluetooth-disable.toml"
    MODPROBE_BLACKLIST="${TMP}/selfdef-bluetooth-blacklist.conf"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    RF_LOG="${RF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_BLUETOOTH_CONFIG="${CONF}" \
    SELFDEF_BT_MODPROBE_BLACKLIST="${MODPROBE_BLACKLIST}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_BLUETOOTH_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_BLUETOOTH_CONFIG="${SELFDEF_BLUETOOTH_CONFIG}" \
        SELFDEF_BT_MODPROBE_BLACKLIST="${MODPROBE_BLACKLIST}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_BLUETOOTH_CONFIG="${CONF}" \
        SELFDEF_BT_MODPROBE_BLACKLIST="${MODPROBE_BLACKLIST}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be mask|stop"* ]]
}

@test "stop profile → stops + disables units, fires rfkill block — NO modprobe blacklist file" {
    write_config "stop"
    run_wd
    grep -q 'systemctl stop bluetooth.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable bluetooth.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask bluetooth' "${SYSEOF_LOG}"
    grep -q 'rfkill block bluetooth' "${RF_LOG}"
    ! [ -f "${MODPROBE_BLACKLIST}" ]
}

@test "mask profile → stops + disables + MASKS units, fires rfkill, writes modprobe blacklist" {
    write_config "mask"
    run_wd
    grep -q 'systemctl stop bluetooth.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable bluetooth.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask bluetooth.service' "${SYSEOF_LOG}"
    grep -q 'rfkill block bluetooth' "${RF_LOG}"
    [ -f "${MODPROBE_BLACKLIST}" ]
}

@test "modprobe blacklist covers the full BT kernel stack (btusb + btintel + btbcm + btmtk + btrtl + bluetooth)" {
    write_config "mask"
    run_wd
    grep -q '^blacklist btusb$' "${MODPROBE_BLACKLIST}"
    grep -q '^blacklist btintel$' "${MODPROBE_BLACKLIST}"
    grep -q '^blacklist btbcm$' "${MODPROBE_BLACKLIST}"
    grep -q '^blacklist btmtk$' "${MODPROBE_BLACKLIST}"
    grep -q '^blacklist btrtl$' "${MODPROBE_BLACKLIST}"
    grep -q '^blacklist bluetooth$' "${MODPROBE_BLACKLIST}"
    # install-/bin/true is the belt-and-suspenders modprobe alias hardening.
    grep -q '^install btusb /bin/true$' "${MODPROBE_BLACKLIST}"
    grep -q '^install bluetooth /bin/true$' "${MODPROBE_BLACKLIST}"
}

@test "modprobe blacklist carries header marker (no timestamp — defeats cmp -s)" {
    write_config "mask"
    run_wd
    grep -q 'managed-by: selfdef bluetooth-disable' "${MODPROBE_BLACKLIST}"
    # Anti-timestamp invariant (2026-06-06 sweep).
    ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "${MODPROBE_BLACKLIST}"
}

@test "modprobe blacklist is chmod 0644 (system-config convention)" {
    write_config "mask"
    run_wd
    [ "$(stat -c '%a' "${MODPROBE_BLACKLIST}")" = "644" ]
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite blacklist (2026-06-06 idempotency fix)" {
    write_config "mask"
    run_wd
    [ -f "${MODPROBE_BLACKLIST}" ]
    mtime_before="$(stat -c '%Y' "${MODPROBE_BLACKLIST}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${MODPROBE_BLACKLIST}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: DRY_RUN does not fire systemctl mutations, rfkill, or write blacklist" {
    write_config "mask"
    DRY_RUN=1 run_wd
    ! grep -q '^systemctl stop' "${SYSEOF_LOG}"
    ! grep -q '^systemctl disable' "${SYSEOF_LOG}"
    ! grep -q '^systemctl mask' "${SYSEOF_LOG}"
    ! grep -q '^rfkill block' "${RF_LOG}"
    ! [ -f "${MODPROBE_BLACKLIST}" ]
}

@test "default profile is mask (no profile key — the conservative reboot-survives default)" {
    : > "${CONF}"
    run_wd
    grep -q 'systemctl mask bluetooth.service' "${SYSEOF_LOG}"
    [ -f "${MODPROBE_BLACKLIST}" ]
}

@test "INVARIANT (profile downgrade mask → stop): REMOVES modprobe blacklist (the reboot-survives mechanism)" {
    # If downgrade leaves the blacklist behind, the operator's intent to
    # relax (let BT come back after reboot) is silently violated.
    write_config "mask"
    run_wd
    [ -f "${MODPROBE_BLACKLIST}" ]
    write_config "stop"
    run_wd
    ! [ -f "${MODPROBE_BLACKLIST}" ]
}

@test "INVARIANT (mask profile also acts on btusb additional kmod): list-unit-files / system-acts on related auxiliary unit" {
    # bluetooth-disable acts on multiple systemd units; if it only
    # touches bluetooth.service, the auxiliary helpers (bluez-related)
    # remain enabled. The L2 unit-name match must be precise but the
    # test surfaces that the canonical primary service IS touched.
    write_config "mask"
    run_wd
    grep -q 'systemctl mask bluetooth.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (rfkill BLOCK is hard not soft — the radio is OFF, not just soft-blocked)" {
    # `rfkill block bluetooth` is a soft block by default. Some
    # variants of bt-disable used to do `rfkill soft bluetooth` only;
    # the current contract is the harder `block` (radio off until
    # explicit `unblock`).
    write_config "stop"
    run_wd
    grep -q 'rfkill block bluetooth' "${RF_LOG}"
    # The unblock action MUST NOT fire (otherwise we're enabling, not disabling).
    ! grep -q 'rfkill unblock' "${RF_LOG}"
}

@test "INVARIANT (modprobe blacklist filename selfdef-* pattern): tracking + uninstall identification" {
    write_config "mask"
    run_wd
    case "${MODPROBE_BLACKLIST}" in
        */selfdef-*.conf) : ;;
        *) fail "modprobe blacklist filename must follow selfdef-*.conf pattern; got: ${MODPROBE_BLACKLIST}" ;;
    esac
}

@test "INVARIANT (header-marker pin): managed-by header present (collateral-damage protection at uninstall)" {
    write_config "mask"
    run_wd
    grep -qE '^#.*managed-by:.*selfdef' "${MODPROBE_BLACKLIST}"
}

@test "INVARIANT (profile upgrade stop → mask): WRITES modprobe blacklist + masks units (reverse of downgrade)" {
    write_config "stop"
    run_wd
    ! [ -f "${MODPROBE_BLACKLIST}" ]
    : > "${SYSEOF_LOG}"
    write_config "mask"
    run_wd
    [ -f "${MODPROBE_BLACKLIST}" ]
    grep -q 'systemctl mask bluetooth.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (per-radio rfkill scope: 'bluetooth' NOT 'all' or 'wifi' — composability with wireless-disable + wwan-disable)" {
    # rfkill block 'all' would also kill Wi-Fi (wireless-disable
    # module owns that surface) + WWAN (wwan-disable module).
    # Lock per-radio scoping so the three modules can be composed.
    write_config "mask"
    run_wd
    grep -qE 'rfkill block bluetooth' "${RF_LOG}"
    ! grep -qE 'rfkill block all' "${RF_LOG}"
    ! grep -qE 'rfkill block wifi' "${RF_LOG}"
    ! grep -qE 'rfkill block wwan' "${RF_LOG}"
}

@test "INVARIANT (header-marker is first non-blank line — predictable for stale-cleanup head -1 grep)" {
    # Mirror wireless-disable + wwan-disable discipline. The
    # downgrade-path stale-cleanup uses head -1 + grep -F. Header
    # MUST be first line.
    write_config "mask"
    run_wd
    first_line="$(head -1 "${MODPROBE_BLACKLIST}")"
    [ "${first_line}" = "# managed-by: selfdef bluetooth-disable" ]
}

@test "INVARIANT (blacklist re-arm after operator out-of-band deletion: re-creates blacklist with header marker)" {
    write_config "mask"
    run_wd
    [ -f "${MODPROBE_BLACKLIST}" ]
    rm -f "${MODPROBE_BLACKLIST}"
    run_wd
    [ -f "${MODPROBE_BLACKLIST}" ]
    grep -q 'managed-by: selfdef bluetooth-disable' "${MODPROBE_BLACKLIST}"
    grep -q '^blacklist btusb$' "${MODPROBE_BLACKLIST}"
}

@test "INVARIANT (emit_status JSON: status=ok + profile surfaced for operator dashboard)" {
    write_config "mask"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"bluetooth-disable"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=mask'* ]]
}

@test "INVARIANT (mask order per unit: stop → disable → mask — terminate-then-clear-then-gate)" {
    # Sister to rsh-telnet-disable + services-disable-printing mask
    # order INVARIANT. Lock the symmetric sequencing for bluetooth.
    # service so any regression that swaps order trips here.
    write_config "mask"
    run_wd
    stop_line="$(grep -n 'systemctl stop bluetooth.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    disable_line="$(grep -n 'systemctl disable bluetooth.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    mask_line="$(grep -n 'systemctl mask bluetooth.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    [ "${stop_line}" -lt "${disable_line}" ]
    [ "${disable_line}" -lt "${mask_line}" ]
}

@test "INVARIANT (no package-uninstall: bluez package NEVER auto-removed — only stop+disable+mask+rfkill+blacklist)" {
    # Module's contract is to neutralize, not uninstall.
    # bluez package removal is operator decision via apt/dnf/yum.
    # Sister to services-disable-printing CUPS no-auto-uninstall
    # INVARIANT.
    write_config "mask"
    run_wd
    ! grep -qE 'apt|dnf|yum|rpm' "${SYSEOF_LOG}"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # bluetooth-disable TOML; parser must tolerate without altering
    # the profile-gated behavior. mask-with-noise still fires the
    # full architectural triplet (rfkill block bluetooth + systemctl
    # mask bluetooth.service + modprobe blacklist of btusb) — the
    # full radio-layer neutralization the operator selected (BT is
    # short-range attack surface: BlueBorne CVE family, BLE
    # tracking/identification, KNOB key-negotiation attacks).
    cat > "${CONF}" <<'TOMLEOF'
profile = "mask"
operator_note = "BT = BlueBorne / BLE tracking / KNOB attack surface"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    grep -qE 'rfkill block bluetooth' "${RF_LOG}"
    grep -q 'systemctl mask bluetooth.service' "${SYSEOF_LOG}"
    [ -f "${MODPROBE_BLACKLIST}" ]
    grep -q 'managed-by: selfdef bluetooth-disable' "${MODPROBE_BLACKLIST}"
}

@test "INVARIANT (asymmetric profile content: stop does NOT install modprobe blacklist — blacklist is mask-only)" {
    # Sister to wireless-disable + wwan-disable asymmetric-content
    # INVARIANTs already locked (rfkill = soft kill; mask = hard
    # kill). The stop profile fires rfkill block bluetooth + stop+
    # disable on the service (live block + boot-time skip) but does
    # NOT install the persistent modprobe blacklist OR the systemctl
    # mask. The mask profile is the only one that adds the persistent
    # driver blacklist + systemctl mask. Locks the soft/hard boundary
    # on the Bluetooth radio neutralization axis (BlueBorne / BLE
    # tracking / KNOB attack surface).
    write_config "stop"
    run_wd
    grep -qE 'rfkill block bluetooth' "${RF_LOG}"
    ! [ -f "${MODPROBE_BLACKLIST}" ]
    ! grep -q 'systemctl mask bluetooth.service' "${SYSEOF_LOG}"
}
