#!/usr/bin/env bats
# L2 functional suite for wireless-disable.
#
# wireless-disable blocks Wi-Fi via rfkill + (mask profile) writes
# a modprobe blacklist preventing the Wi-Fi kernel modules from
# auto-loading on next boot. On a sovereign endpoint without Wi-Fi
# use, the Wi-Fi stack is pure attack surface: KARMA/evil-AP
# attacks, captive-portal MITM, even pre-association attacks
# (KRACK/etc.) all become irrelevant if the radio is dead.
#
# Profiles:
#   rfkill → runtime block only (re-enables on reboot until
#            re-applied)
#   mask   → rfkill block + persistent kernel-module blacklist
#            (the Wi-Fi stack is unloadable until removal)
#
# CRITICAL INVARIANTS this suite locks:
#   - mask profile writes a header-marker on the blacklist file
#     (so stale-file cleanup can identify selfdef-managed files).
#   - rfkill profile DOWNGRADE from mask REMOVES the blacklist
#     file (no stale modprobe rules from prior mask profile).
#   - Stale-file removal CHECKS the header marker — won't touch
#     modprobe.d files NOT owned by selfdef.
#   - DRY_RUN protects rfkill + blacklist file.
#
# Uses SELFDEF_WIRELESS_MODPROBE_FILE env-var (added 2026-06-06)
# for L2 testability.
#
# Run with: bats packaging/test/L2-wireless-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/rfkill" <<'RFEOF'
#!/usr/bin/env bash
printf 'rfkill %s\n' "$*" >> "${RF_LOG}"
exit 0
RFEOF
    chmod +x "${BIN}/rfkill"
    export RF_LOG="${TMP}/rfkill.log"
    : > "${RF_LOG}"
    CONF="${TMP}/wireless-disable.toml"
    MODPROBE_FILE="${TMP}/selfdef-wireless-blacklist.conf"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    RF_LOG="${RF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_WIRELESS_CONFIG="${CONF}" \
    SELFDEF_WIRELESS_MODPROBE_FILE="${MODPROBE_FILE}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_WIRELESS_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_WIRELESS_CONFIG="${SELFDEF_WIRELESS_CONFIG}" \
        SELFDEF_WIRELESS_MODPROBE_FILE="${MODPROBE_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_WIRELESS_CONFIG="${CONF}" \
        SELFDEF_WIRELESS_MODPROBE_FILE="${MODPROBE_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be rfkill|mask"* ]]
}

@test "rfkill profile blocks Wi-Fi via rfkill — NO modprobe blacklist file" {
    write_config "rfkill"
    run_wd
    grep -q 'rfkill block wifi' "${RF_LOG}"
    ! [ -f "${MODPROBE_FILE}" ]
}

@test "mask profile blocks via rfkill AND writes modprobe blacklist" {
    write_config "mask"
    run_wd
    grep -q 'rfkill block wifi' "${RF_LOG}"
    [ -f "${MODPROBE_FILE}" ]
    grep -q 'managed-by: selfdef wireless-disable' "${MODPROBE_FILE}"
}

@test "modprobe blacklist content covers the full Wi-Fi stack (cfg80211 + mac80211 + drivers)" {
    write_config "mask"
    run_wd
    # Core stack.
    grep -q 'blacklist cfg80211' "${MODPROBE_FILE}"
    grep -q 'blacklist mac80211' "${MODPROBE_FILE}"
    # Common drivers.
    grep -q 'blacklist iwlwifi' "${MODPROBE_FILE}"
    grep -q 'blacklist ath9k' "${MODPROBE_FILE}"
    # install $m /bin/true — secondary protection against transient load.
    grep -q 'install cfg80211 /bin/true' "${MODPROBE_FILE}"
    grep -q 'install mac80211 /bin/true' "${MODPROBE_FILE}"
}

@test "INVARIANT: profile downgrade mask → rfkill REMOVES the blacklist file" {
    write_config "mask"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    write_config "rfkill"
    run_wd
    ! [ -f "${MODPROBE_FILE}" ]
}

@test "INVARIANT: non-selfdef-owned blacklist file is LEFT ALONE (collateral-damage protection)" {
    write_config "rfkill"
    # Operator pre-staged a blacklist file with a different header.
    printf '%s\n' '# managed-by: somebody-else' 'blacklist some-mod' > "${MODPROBE_FILE}"
    run_wd
    # File still present — selfdef won't touch what it didn't create.
    [ -f "${MODPROBE_FILE}" ]
    grep -q 'somebody-else' "${MODPROBE_FILE}"
}

@test "modprobe blacklist file is chmod 0644 (system-config convention)" {
    write_config "mask"
    run_wd
    [ "$(stat -c '%a' "${MODPROBE_FILE}")" = "644" ]
}

@test "INVARIANT: DRY_RUN does not write blacklist file or fire rfkill" {
    write_config "mask"
    DRY_RUN=1 run_wd
    ! [ -f "${MODPROBE_FILE}" ]
    ! grep -q 'rfkill block wifi' "${RF_LOG}"
}

@test "default profile is rfkill (no profile key — the conservative default)" {
    : > "${CONF}"
    run_wd
    grep -q 'rfkill block wifi' "${RF_LOG}"
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
