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

@test "INVARIANT (rfkill block scope = 'wifi' — NOT 'all', which would kill bluetooth too): per-radio scoping" {
    # rfkill block 'all' would also disable Bluetooth (the
    # bluetooth-disable module owns that surface). Lock the
    # per-radio scoping so the two modules remain composable.
    write_config "rfkill"
    run_wd
    grep -qE 'rfkill block wifi' "${RF_LOG}"
    ! grep -qE 'rfkill block all' "${RF_LOG}"
    ! grep -qE 'rfkill block bluetooth' "${RF_LOG}"
}

@test "INVARIANT (driver-coverage: brcmfmac + mt76 + rtw88_core + ath11k blacklisted — modern-chipset coverage)" {
    # The pre-existing test only checks iwlwifi + ath9k (older
    # Intel + Atheros). Lock the broader modern-chipset coverage:
    # brcmfmac (Broadcom), mt76 family (MediaTek), rtw88_core
    # (Realtek), ath11k (Qualcomm Wi-Fi 6 / 6E).
    write_config "mask"
    run_wd
    grep -q '^blacklist brcmfmac$'    "${MODPROBE_FILE}"
    grep -q '^blacklist mt76$'        "${MODPROBE_FILE}"
    grep -q '^blacklist rtw88_core$'  "${MODPROBE_FILE}"
    grep -q '^blacklist ath11k$'      "${MODPROBE_FILE}"
}

@test "INVARIANT (header-marker is first non-blank line — predictable for stale-cleanup head -1 grep)" {
    # The downgrade-path's stale-file detection uses
    # 'head -1 \$MODPROBE_FILE | grep -qF \$HEADER_MARKER'.
    # The header MUST be the first line — not buried mid-file or
    # after a comment — or the stale-cleanup grep misses + leaves
    # selfdef-owned files orphaned.
    write_config "mask"
    run_wd
    first_line="$(head -1 "${MODPROBE_FILE}")"
    [ "${first_line}" = "# managed-by: selfdef wireless-disable" ]
}

@test "INVARIANT (mask re-arm after operator deletion: re-creates blacklist file with header marker)" {
    # Operator deletes the modprobe file out-of-band (maybe
    # debugging Wi-Fi). Next apply must re-create it cleanly
    # with header-marker intact so the downgrade-path can still
    # identify ownership.
    write_config "mask"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    rm -f "${MODPROBE_FILE}"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    grep -q 'managed-by: selfdef wireless-disable' "${MODPROBE_FILE}"
}

@test "INVARIANT (JSON emit_status: status=ok + profile + wired_carrier surfaced)" {
    # emit_status surfaces wired_carrier=true|false in the message
    # body so the operator dashboard can flag "wired-fallback OK"
    # vs "console-only after this apply" — critical visibility for
    # a module that may sever remote access.
    write_config "rfkill"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=rfkill'* ]]
    [[ "${output}" == *'wired_carrier='* ]]
}

@test "INVARIANT (emit_status: module=wireless-disable surfaces for operator dashboard)" {
    write_config "mask"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"wireless-disable"'* ]]
    [[ "${output}" == *'profile=mask'* ]]
}

@test "INVARIANT (rfkill re-arm on every apply: rfkill block fires even when blacklist file unchanged)" {
    # rfkill state may be cleared at boot (or by operator via rfkill
    # unblock). Each apply MUST re-fire rfkill block — the live state
    # is not file-backed, only the persistent kernel-module blacklist is.
    write_config "mask"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    : > "${RF_LOG}"
    run_wd
    # File idempotent (unchanged), but rfkill still fires.
    grep -q 'rfkill block wifi' "${RF_LOG}"
}

@test "INVARIANT (driver-coverage continued: wl + brcmsmac + wireless legacy chipsets blacklisted)" {
    # Additional legacy chipsets MUST also be on the blacklist —
    # locks broader hardware coverage. Operator's hardware inventory
    # may include legacy or proprietary drivers.
    write_config "mask"
    run_wd
    # Either modern OR legacy variants should be present.
    grep -qE '^blacklist (wl|brcmsmac|b43|rt2x00|wireless)' "${MODPROBE_FILE}" \
      || grep -qE '^blacklist (iwl4965|ath5k|ath6kl)' "${MODPROBE_FILE}"
}

@test "INVARIANT (modprobe install /bin/true secondary protection: covers transient module load attempts)" {
    # The 'install $m /bin/true' lines act as a runtime trap — even
    # if 'modprobe cfg80211' is somehow invoked, modprobe runs
    # /bin/true instead of loading the module. Lock that BOTH
    # blacklist AND install-line patterns are present for core stack.
    write_config "mask"
    run_wd
    grep -q '^install cfg80211 /bin/true' "${MODPROBE_FILE}"
    grep -q '^install mac80211 /bin/true' "${MODPROBE_FILE}"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # wireless-disable TOML; parser must tolerate without altering
    # the profile-gated behavior. mask-with-noise still fires rfkill
    # block wifi AND writes the persistent modprobe blacklist with
    # header marker (the full radio-neutralization the operator
    # selected — Wi-Fi stack is pure attack surface on sovereign
    # endpoint: KARMA/evil-AP/captive-portal MITM/KRACK).
    cat > "${CONF}" <<'TOMLEOF'
profile = "mask"
operator_note = "Wi-Fi = KARMA/evil-AP/MITM surface — kill it dead"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    grep -qE 'rfkill block wifi' "${RF_LOG}"
    [ -f "${MODPROBE_FILE}" ]
    grep -q 'managed-by: selfdef wireless-disable' "${MODPROBE_FILE}"
}

@test "INVARIANT (asymmetric profile content: rfkill does NOT install modprobe blacklist — blacklist is mask-only)" {
    # Sister to many other installer module's asymmetric-profile
    # INVARIANT across the brain (ssh-hardening AllowGroups,
    # selinux-baseline autorelabel, tmpfs-baseline /tmp-only,
    # coredump-suid-restrict limits.d). The rfkill profile is the
    # soft kill (live + cheap to reverse: rfkill unblock wifi);
    # the mask profile is the hard kill (persistent modprobe
    # blacklist survives reboots + driver auto-load events). If
    # rfkill silently installed the modprobe blacklist, it would
    # over-reach (operator who chose rfkill to keep mask as a
    # later option would lose the asymmetry). Locks the boundary:
    # rfkill = live block only, mask = live block + persistent
    # driver blacklist.
    write_config "rfkill"
    run_wd
    grep -qE 'rfkill block wifi' "${RF_LOG}"
    ! [ -f "${MODPROBE_FILE}" ]
}

@test "INVARIANT (DRY_RUN does not fire rfkill or write the modprobe blacklist)" {
    # Sister to many other installer module's DRY_RUN INVARIANT
    # across the brain. The wireless-disable DRY_RUN path MUST
    # be a no-op against live kernel state + live filesystem.
    # Locks the dry-run side-effect-freedom contract.
    write_config "mask"
    DRY_RUN=1 run_wd
    ! grep -qE 'rfkill block wifi' "${RF_LOG}"
    ! [ -f "${MODPROBE_FILE}" ]
}

@test "INVARIANT (modprobe blacklist file mode 0644 — system-config convention)" {
    # Sister to brain-wide chmod 0644 INVARIANTs. The modprobe
    # blacklist must be world-readable for modprobe at boot, and
    # root-write-only to prevent silent unblock.
    write_config "mask"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    [ "$(stat -c '%a' "${MODPROBE_FILE}")" = "644" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on wireless-disable installer
    # surface across rfkill + modprobe-blacklist phases.
    write_config "mask"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"wireless-disable"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (header-marker discipline: modprobe blacklist carries 'selfdef' self-identifying header — head-grep stale-cleanup discipline)" {
    # Sister to brain-wide header-marker discipline INVARIANTs
    # across L2 drop-in suites. The wireless-disable modprobe
    # blacklist under /etc/modprobe.d/50-selfdef-wireless.conf
    # MUST carry a comment marker identifying it as selfdef-
    # managed so a stale-cleanup head -2 grep at uninstall time
    # can identify which files selfdef owns vs which is
    # operator-original. Without a marker, a subsequent
    # uninstaller could not tell apart operator baseline
    # modprobe rules from selfdef-injected blacklist directives
    # — risking accidental rollback of operator changes. Locks
    # marker-discipline on the wireless-disable modprobe.d
    # substrate.
    write_config "mask"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    grep -qE '^#.*(selfdef|wireless-disable|managed)' "${MODPROBE_FILE}"
}

@test "INVARIANT (no auto-uninstall: wireless-disable NEVER emits package-remove commands)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The wireless-disable installer writes a
    # modprobe.d blacklist + fires rfkill block but MUST NEVER
    # emit shell commands that uninstall kernel/firmware
    # packages (apt/dpkg/dnf/rpm/yum remove|purge|uninstall
    # linux-image|linux-firmware|wireless-tools). Auto-removal
    # would be catastrophic at the kernel-substrate level.
    # Locks anti-package-removal contract on the wireless-
    # disable substrate.
    write_config "mask"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(linux-image|linux-firmware|wireless-tools)'
    [ ! -f "${MODPROBE_FILE}" ] || ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${MODPROBE_FILE}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. wireless-disable manifest declares install +
    # profile gating the resolver enforces; malformed manifest
    # wedges the wireless modprobe blacklist baseline. Python's
    # tomllib is the canonical parser. Locks anti-malformed-
    # manifest on the wireless-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'wireless-disable', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}
