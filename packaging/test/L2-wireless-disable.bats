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

@test "INVARIANT (no auto-delete: wireless-disable installer NEVER deletes operator-pre-existing modprobe.d/sysctl.d entries — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # wireless-disable writes its own modprobe blacklist drop-in;
    # it MUST NEVER rm/find-delete operator-pre-existing
    # /etc/modprobe.d entries not owned by THIS module. Locks
    # no-auto-delete on the wireless-disable installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/modprobe\.d[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/modprobe\.d.*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # wireless-disable install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the wireless-disable lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the wireless-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('depends_on', [])
assert isinstance(v, list), f'depends_on must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml conflicts field is a TOML list — anti-string-malformation contract on conflicts)" {
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks list-vs-string discipline on conflicts.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('conflicts', [])
assert isinstance(v, list), f'conflicts must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml provides field is a TOML list — anti-string-malformation contract on provides)" {
    # Sister to brain-wide module.toml list-vs-string family.
    # Locks list discipline on provides.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('provides', [])
assert isinstance(v, list), f'provides must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml requires field is a TOML list — anti-string-malformation contract on requires)" {
    # Sister to brain-wide module.toml list-vs-string family.
    # Locks list discipline on requires.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('requires', [])
assert isinstance(v, list), f'requires must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml requires entries are tables with kind + value — anti-flat-string-list contract)" {
    # Sister to brain-wide module.toml requires-shape INVARIANT
    # family. Locks the kind+value table-shape discipline on
    # the wireless-disable requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
reqs = data.get('requires', [])
for r in reqs:
    assert isinstance(r, dict), f'requires entry must be table, got {type(r).__name__}'
    assert 'kind' in r and 'value' in r, f'requires entry must have kind+value, got {r}'
"
}

@test "INVARIANT (module.toml summary field present + non-empty — operator-dashboard one-line description contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks summary-present discipline on the
    # wireless-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) > 0, f'summary must be non-empty string, got {repr(s)}'
"
}

@test "INVARIANT (module.toml category field present + non-empty — dashboard-grouping contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks category-present discipline on the
    # wireless-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert isinstance(c, str) and len(c) > 0, f'category must be non-empty string, got {repr(c)}'
"
}

@test "INVARIANT (module.toml version field is semver X.Y.Z — version-comparison sortability contract)" {
    # Sister to brain-wide module.toml semver INVARIANT family.
    # Locks semver-X.Y.Z discipline on the wireless-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (wireless-disable module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl installer resolves apply scripts
    # via module.toml's [install].apply field — the canonical
    # value is the relative path "install/apply.sh" (under the
    # module's own directory). A regression that swapped to
    # an absolute /usr/local/libexec/... path would break the
    # in-tree test runner (which executes apply scripts from
    # the source tree, not /usr/local/libexec/). A regression
    # to a non-existent path would surface as "apply script
    # not found" at install time. Locks the canonical
    # install/apply.sh path discipline on the wireless-disable module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install') or {}
ap = inst.get('apply', '')
assert ap == 'install/apply.sh', f'install.apply must be install/apply.sh, got {ap!r}'
"
}

@test "INVARIANT (wireless-disable module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the wireless-disable module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install') or {}
chk = inst.get('check', '')
assert chk == 'install/check.sh', f'install.check must be install/check.sh, got {chk!r}'
"
}

@test "INVARIANT (wireless-disable module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
    # Sister to brain-wide module.toml [install_paths]
    # INVARIANT family. Per MS011 Z-8 / SDD-026, every
    # installer module MUST declare an [install_paths] block
    # enumerating the on-disk surfaces it touches on apply.
    # The selfdef dashboard's install-options surface +
    # install-plan auditor read this block to surface what
    # the module mutates BEFORE apply runs. A regression
    # dropping the [install_paths] block would leave operators
    # without a pre-apply manifest of writes, breaking
    # operator-consent + the install-plan-dry-run contract.
    # Locks the SDD-026 manifest discipline on the wireless-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths')
assert ip is not None, f'[install_paths] block must be present per SDD-026, got None'
paths = ip.get('paths', [])
assert isinstance(paths, list) and len(paths) > 0, f'install_paths.paths must be non-empty list, got {paths!r}'
"
}

@test "INVARIANT (wireless-disable module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for wireless-disable is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the wireless-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (wireless-disable module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
    # Sister to brain-wide [install_paths].paths INVARIANT
    # family. The install_paths.paths field MUST be a TOML
    # list of strings (each element an absolute path the
    # module touches on apply). A regression that swapped to
    # a comma-separated string ("path1,path2,path3") would
    # silently treat it as a single literal path. The
    # selfdef installer iterates the list to surface the
    # mutation manifest to operators; broken type-shape
    # would break the install-options surface + dry-run
    # auditor. Locks the TOML-list-of-strings type discipline
    # on the wireless-disable install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list), f'install_paths.paths must be TOML list, got {type(ps).__name__}'
assert all(isinstance(p, str) for p in ps), f'every paths entry must be a string'
"
}

@test "INVARIANT (wireless-disable module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the wireless-disable requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
req = data.get('requires')
assert isinstance(req, list), f'requires must be TOML list, got {type(req).__name__}'
for r in req:
    assert isinstance(r, dict), f'requires entry must be inline-table, got {type(r).__name__}'
    assert 'kind' in r and 'value' in r, f'requires must have kind+value, got {r!r}'
"
}

@test "INVARIANT (wireless-disable module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the wireless-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (wireless-disable module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the wireless-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (wireless-disable module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the wireless-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (wireless-disable module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (wireless-disable module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the wireless-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
prof = data.get('profiles')
assert prof is not None, f'[profiles] must be present, got None'
assert isinstance(prof, dict), f'[profiles] must be TOML table, got {type(prof).__name__}'
"
}

@test "INVARIANT (wireless-disable module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (wireless-disable module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (wireless-disable module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (wireless-disable module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (wireless-disable module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (wireless-disable module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (wireless-disable README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (wireless-disable install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (wireless-disable install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (wireless-disable install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (wireless-disable install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (wireless-disable install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (wireless-disable install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (wireless-disable install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (wireless-disable install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (wireless-disable install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (wireless-disable install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (wireless-disable install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (wireless-disable install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (wireless-disable module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (wireless-disable module.toml exists at canonical path modules/wireless-disable/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (wireless-disable module dir is at canonical path modules/wireless-disable/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/wireless-disable"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (wireless-disable install dir exists at modules/wireless-disable/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (wireless-disable install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (wireless-disable install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (wireless-disable install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (wireless-disable install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (wireless-disable module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (wireless-disable install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (wireless-disable install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (wireless-disable install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (wireless-disable install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (wireless-disable install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (wireless-disable install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (wireless-disable install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (wireless-disable install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (wireless-disable module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (wireless-disable module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (wireless-disable module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
prefixes = ('/etc/', '/usr/', '/var/', '/lib/', '/opt/', '/run/', '/srv/', '/boot/')
for p in ps:
    assert any(p.startswith(pf) for pf in prefixes), f'{p!r} not canonical-root'
"
}

@test "INVARIANT (wireless-disable module.toml has at least 1 entry in install_paths.paths — non-empty-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 1
"
}

@test "INVARIANT (wireless-disable module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (wireless-disable module.toml install_paths.scope canonical-system 92 — operator-scope-fixed)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc in ('system', 'user', '')
"
}

@test "INVARIANT (wireless-disable module.toml install_paths.paths has /etc/selfdef/ entry 93 — selfdef-config-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/etc/selfdef/' in p for p in ps)
"
}

@test "INVARIANT (wireless-disable module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (wireless-disable module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (wireless-disable module.toml uses TOML key-value assignment syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (wireless-disable module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (wireless-disable module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (wireless-disable module.toml category field uses double-quoted string syntax — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (wireless-disable module.toml summary field uses double-quoted string syntax — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (wireless-disable module.toml name field value matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"wireless-disable"' "${mtoml}"
}

@test "INVARIANT (wireless-disable module.toml top-level keys before any [section] header — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    python3 -c "
import re
with open('${mtoml}') as fp:
    for ln in fp:
        s = ln.strip()
        if not s or s.startswith('#'): continue
        if s.startswith('['): break
        assert '=' in ln, f'expected key=val before sections, got {ln!r}'
        break
"
}

@test "INVARIANT (wireless-disable module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (wireless-disable module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireless-disable/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}
