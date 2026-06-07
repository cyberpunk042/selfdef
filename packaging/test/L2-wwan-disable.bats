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

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # wwan-disable TOML; parser must tolerate without altering the
    # profile-gated behavior. mask-with-noise still fires the full
    # architectural triplet (rfkill block wwan + ModemManager mask
    # + persistent modprobe blacklist) — the full remote-attack-
    # surface neutralization the operator selected (carrier OTA
    # pushes / Stingray / baseband CVEs all become irrelevant if the
    # modem is dead).
    cat > "${CONF}" <<'TOMLEOF'
profile = "mask"
operator_note = "WWAN = carrier OTA + Stingray + baseband CVE surface"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    grep -q 'rfkill block wwan' "${RF_LOG}"
    grep -q 'systemctl mask ModemManager.service' "${SYSEOF_LOG}"
    [ -f "${MODPROBE_FILE}" ]
    grep -q 'managed-by: selfdef wwan-disable' "${MODPROBE_FILE}"
}

@test "INVARIANT (asymmetric profile content: rfkill does NOT install modprobe blacklist — blacklist is mask-only)" {
    # Sister to wireless-disable asymmetric-content INVARIANT just
    # locked (rfkill = soft kill; mask = hard kill). The rfkill
    # profile fires rfkill block wwan + ModemManager mask (the
    # always-included architectural complement per the prior
    # INVARIANT) but does NOT install the persistent modprobe
    # blacklist. The mask profile is the only one that adds the
    # persistent driver blacklist. Locks the soft/hard boundary
    # on the WWAN radio neutralization axis (carrier OTA + Stingray
    # + baseband CVE surface).
    write_config "rfkill"
    run_wd
    grep -q 'rfkill block wwan' "${RF_LOG}"
    ! [ -f "${MODPROBE_FILE}" ]
}

@test "INVARIANT (DRY_RUN does not fire rfkill or systemctl mask or write the modprobe blacklist)" {
    # Sister to wireless-disable + many other installer module's
    # DRY_RUN INVARIANT across the brain. The wwan-disable
    # DRY_RUN path MUST be a no-op against live kernel state +
    # systemd state + filesystem. Locks the dry-run side-effect-
    # freedom contract.
    write_config "mask"
    DRY_RUN=1 run_wd
    ! grep -qE 'rfkill block wwan' "${RF_LOG}"
    ! grep -qE 'systemctl mask' "${SYSEOF_LOG}"
    ! [ -f "${MODPROBE_FILE}" ]
}

@test "INVARIANT (modprobe blacklist file mode 0644 — system-config convention)" {
    # Sister to brain-wide chmod 0644 INVARIANTs (wireless-disable
    # / bluetooth-disable / many others). The wwan modprobe
    # blacklist must be world-readable (modprobe reads at boot)
    # and root-write-only to prevent silent unblock.
    write_config "mask"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    [ "$(stat -c '%a' "${MODPROBE_FILE}")" = "644" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on wwan-disable installer surface
    # across rfkill + ModemManager-mask + modprobe-blacklist
    # phases (the architectural-triplet).
    write_config "mask"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"wwan-disable"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (header-marker discipline: modprobe blacklist carries 'selfdef' self-identifying header — head-grep stale-cleanup discipline)" {
    # Sister to brain-wide header-marker discipline INVARIANTs
    # across L2 drop-in suites. The wwan-disable modprobe
    # blacklist under /etc/modprobe.d/50-selfdef-wwan.conf MUST
    # carry a comment marker identifying it as selfdef-managed
    # so a stale-cleanup head -2 grep at uninstall time can
    # identify which files selfdef owns vs which is operator-
    # original. Without a marker, a subsequent uninstaller
    # could not tell apart operator baseline modprobe rules
    # from selfdef-injected blacklist directives — risking
    # accidental rollback of operator changes. Locks marker-
    # discipline on the wwan-disable modprobe.d substrate.
    write_config "mask"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    grep -qE '^#.*(selfdef|wwan-disable|managed)' "${MODPROBE_FILE}"
}

@test "INVARIANT (no auto-uninstall: wwan-disable NEVER emits package-remove commands)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The wwan-disable installer writes a modprobe.d
    # blacklist + masks ModemManager + fires rfkill but MUST
    # NEVER emit shell commands that uninstall kernel/firmware
    # packages (apt/dpkg/dnf/rpm/yum remove|purge|uninstall
    # linux-image|linux-firmware|modemmanager). Auto-removal
    # would be catastrophic at the kernel-substrate level.
    # Locks anti-package-removal contract on the wwan-disable
    # substrate.
    write_config "mask"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(linux-image|linux-firmware|modemmanager)'
    [ ! -f "${MODPROBE_FILE}" ] || ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${MODPROBE_FILE}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. wwan-disable manifest declares install + profile
    # gating the resolver enforces; malformed manifest wedges
    # the WWAN modprobe blacklist baseline. Python's tomllib is
    # the canonical parser. Locks anti-malformed-manifest on
    # the wwan-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'wwan-disable', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: wwan-disable installer NEVER deletes operator-pre-existing modprobe.d/sysctl.d entries — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # wwan-disable writes its own modprobe blacklist drop-in;
    # it MUST NEVER rm/find-delete operator-pre-existing
    # /etc/modprobe.d entries not owned by THIS module. Locks
    # no-auto-delete on the wwan-disable installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/modprobe\.d[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/modprobe\.d.*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # wwan-disable install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the wwan-disable lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the wwan-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('provides', [])
assert isinstance(v, list), f'provides must be list, got {type(v).__name__}'
"
}
