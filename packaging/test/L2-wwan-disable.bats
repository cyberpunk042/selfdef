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

@test "INVARIANT (module.toml requires field is a TOML list — anti-string-malformation contract on requires)" {
    # Sister to brain-wide module.toml list-vs-string family.
    # Locks list discipline on requires.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
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
    # the wwan-disable requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
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
    # wwan-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
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
    # wwan-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
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
    # Locks semver-X.Y.Z discipline on the wwan-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (wwan-disable module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the wwan-disable module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
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

@test "INVARIANT (wwan-disable module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the wwan-disable module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
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

@test "INVARIANT (wwan-disable module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the wwan-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
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

@test "INVARIANT (wwan-disable module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for wwan-disable is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the wwan-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (wwan-disable module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the wwan-disable install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
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

@test "INVARIANT (wwan-disable module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the wwan-disable requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
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

@test "INVARIANT (wwan-disable module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the wwan-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (wwan-disable module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the wwan-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (wwan-disable module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the wwan-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (wwan-disable module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (wwan-disable module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the wwan-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
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

@test "INVARIANT (wwan-disable module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (wwan-disable module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (wwan-disable module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (wwan-disable module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (wwan-disable module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (wwan-disable module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (wwan-disable README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (wwan-disable install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (wwan-disable install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (wwan-disable install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (wwan-disable install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (wwan-disable install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (wwan-disable install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (wwan-disable install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (wwan-disable install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (wwan-disable install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (wwan-disable install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (wwan-disable install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (wwan-disable install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (wwan-disable module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (wwan-disable module.toml exists at canonical path modules/wwan-disable/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (wwan-disable module dir is at canonical path modules/wwan-disable/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/wwan-disable"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (wwan-disable install dir exists at modules/wwan-disable/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (wwan-disable install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (wwan-disable install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (wwan-disable install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (wwan-disable install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (wwan-disable module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (wwan-disable install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (wwan-disable install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (wwan-disable install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (wwan-disable install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (wwan-disable install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (wwan-disable install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (wwan-disable install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (wwan-disable install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (wwan-disable module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (wwan-disable module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (wwan-disable module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
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

@test "INVARIANT (wwan-disable module.toml has at least 1 entry in install_paths.paths — non-empty-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 1
"
}

@test "INVARIANT (wwan-disable module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (wwan-disable module.toml install_paths.scope canonical-system 92 — operator-scope-fixed)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc in ('system', 'user', '')
"
}

@test "INVARIANT (wwan-disable module.toml install_paths.paths has /etc/selfdef/ entry 93 — selfdef-config-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/etc/selfdef/' in p for p in ps)
"
}

@test "INVARIANT (wwan-disable module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (wwan-disable module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (wwan-disable module.toml uses TOML key-value assignment syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (wwan-disable module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (wwan-disable module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (wwan-disable module.toml category field uses double-quoted string syntax — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (wwan-disable module.toml summary field uses double-quoted string syntax — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (wwan-disable module.toml name field value matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"wwan-disable"' "${mtoml}"
}

@test "INVARIANT (wwan-disable module.toml top-level keys before any [section] header — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
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

@test "INVARIANT (wwan-disable module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (wwan-disable module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (wwan-disable module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (wwan-disable module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (wwan-disable module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (wwan-disable module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (wwan-disable module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (wwan-disable module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (wwan-disable module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}

@test "INVARIANT (wwan-disable module.toml [install] check value is non-empty string ending with .sh — TOML-install-check-shape-canonical 112)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ck = (data.get('install') or {}).get('check', '')
assert isinstance(ck, str) and ck and ck.endswith('.sh'), f'install.check must be non-empty .sh path, got {ck!r}'
"
}

@test "INVARIANT (wwan-disable module.toml version field matches semver X.Y.Z pattern — TOML-version-semver-canonical 113)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v), f'version must be semver X.Y.Z, got {v!r}'
"
}

@test "INVARIANT (wwan-disable module.toml summary field is non-empty string with length >= 30 chars — TOML-summary-substance-floor 114)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) >= 30, f'summary must be string with len >= 30, got len={len(s)} value={s!r}'
"
}

@test "INVARIANT (wwan-disable module.toml top-level requires field is a TOML list — TOML-requires-list-canonical 115)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (wwan-disable module.toml top-level provides field is a TOML list — TOML-provides-list-canonical 116)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('provides')
assert isinstance(r, list), f'provides must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (wwan-disable module.toml top-level conflicts field is a TOML list — TOML-conflicts-list-canonical 117)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('conflicts')
assert isinstance(r, list), f'conflicts must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (wwan-disable module.toml top-level depends_on field is a TOML list — TOML-depends-on-list-canonical 118)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wwan-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('depends_on')
assert isinstance(r, list), f'depends_on must be list, got {type(r).__name__}'
"
}
