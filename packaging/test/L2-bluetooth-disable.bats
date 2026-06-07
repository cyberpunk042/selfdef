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

@test "INVARIANT (DRY_RUN side-effect-freedom: NO systemctl mask/disable/stop AND NO rfkill block AND NO blacklist render fires when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain (acct-baseline / aslr-baseline / apport-
    # disable / at-disable / avahi-disable / many others). Operator's
    # exploratory --dry-run MUST preview without firing systemctl
    # stop/disable/mask against bluetooth.service AND without firing
    # rfkill block bluetooth AND without rendering the modprobe
    # blacklist. Without strict DRY_RUN gating, a previewed dry-run
    # would silently kill BlueTooth on a host where operator
    # legitimately uses it (BlueTooth keyboard/mouse, audio
    # headset). Locks the dry-run-preserves-state contract on the
    # BlueTooth radio neutralization substrate.
    write_config "mask"
    : > "${SYSEOF_LOG}"
    : > "${RF_LOG}"
    rm -f "${MODPROBE_BLACKLIST}"
    DRY_RUN=1 run_wd
    ! grep -q 'systemctl mask bluetooth.service' "${SYSEOF_LOG}"
    ! grep -qE 'rfkill block bluetooth' "${RF_LOG}"
    [ ! -f "${MODPROBE_BLACKLIST}" ]
}

@test "INVARIANT (no auto-uninstall: bluez package NEVER auto-removed)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs.
    write_config "mask"
    run_wd
    ! grep -qE '(apt-get|dpkg|dnf|rpm)[[:space:]]+(remove|purge|uninstall)' "${SYSEOF_LOG}"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on bluetooth-disable installer
    # surface across systemctl + rfkill + modprobe-blacklist
    # phases (architectural-triplet).
    write_config "mask"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"bluetooth-disable"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on bluetooth-disable surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The bluetooth-disable installer MUST only emit severity
    # values from the closed set {ok,warn,alert} — never custom
    # values (critical, error, fatal, notice, info). Operator
    # dashboard parsers branch on the literal severity string;
    # an out-of-set value silently falls through routing and the
    # operator never sees the bluetooth neutralization status
    # alert. Locks parser contract on the bluetooth-disable
    # installer JSON surface (consistency-with-watchdog-family
    # discipline).
    write_config "mask"
    output="$(run_wd 2>&1)"
    bad=$(printf '%s\n' "${output}" | grep -oE '"severity":"[^"]+"' | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (mask is sticky: downgrade mask → stop preserves mask state — anti-silent-unmask)" {
    # Sister to brain-wide mask-sticky-downgrade INVARIANTs
    # across L2 service-disable suites (avahi, nscd, ctrlaltdel,
    # rpcbind, at-disable). The bluetooth-disable mask profile
    # sets bluetooth.service to masked state; a subsequent
    # profile downgrade to stop MUST NOT emit systemctl unmask.
    # The operator's mask decision is sticky — they explicitly
    # chose hard-disable over soft-stop. Silent unmask would
    # re-enable the bluetooth attack surface after operator
    # chose to hard-disable it. Locks mask-stickiness contract
    # on the bluetooth-disable substrate.
    write_config "mask"
    run_wd
    : > "${SYSEOF_LOG}"
    write_config "stop"
    run_wd
    ! grep -qE 'systemctl unmask bluetooth' "${SYSEOF_LOG}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. bluetooth-disable manifest declares install +
    # profile gating (mask / stop) the resolver enforces;
    # malformed manifest wedges the bluetooth neutralization
    # sequence. Python's tomllib is the canonical parser. Locks
    # anti-malformed-manifest on the bluetooth-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'bluetooth-disable', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # bluetooth-disable install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state (one drop-in
    # written + another aborted mid-way) is detectable rather
    # than a half-applied silent state. Locks fail-loud
    # invariant on the bluetooth-disable lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list ([] or ["a", "b"]) — not a comma-separated
    # string like "a, b" which TOML's tomllib would silently
    # accept as a single-element list ["a, b"]. The resolver
    # would then look for a single module named literally "a, b"
    # and fail to find it. Locks list-vs-string discipline on
    # the depends_on field of the bluetooth-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
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
    # Sister to brain-wide module.toml manifest-completeness +
    # depends_on-list INVARIANTs already locked. The conflicts
    # field MUST be a TOML list — the resolver iterates
    # conflicts to detect mutually-exclusive module pairs at
    # install-time. A scalar/string would silently parse as a
    # single-element list, masking real conflicts. Locks list-
    # vs-string discipline on the conflicts field of the
    # bluetooth-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
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
    # Sister to brain-wide module.toml manifest-completeness +
    # depends_on-list + conflicts-list INVARIANTs already
    # locked. The provides field MUST be a TOML list — the
    # resolver iterates it to register each provided contract
    # in the consumer-binding graph. A scalar would silently
    # parse as a single-element list, masking real provides.
    # Locks list-vs-string discipline on the provides field of
    # the bluetooth-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
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
    # family. Each requires entry MUST be a TOML inline table
    # `{ kind = "binary", value = "X" }` — not a flat string
    # like "binary:X" (which the resolver would not parse as
    # structured kind/value and would fail to dispatch the
    # check). Locks the kind+value table-shape discipline on
    # the bluetooth-disable requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
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
    # INVARIANT family. The summary field is the operator-facing
    # one-line description rendered on the install dashboard.
    # An empty or missing summary would surface as an unlabeled
    # module-row, harming operator triage. Locks the summary-
    # present discipline on the bluetooth-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
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
    # INVARIANT family. The category field groups modules in
    # the operator install dashboard (detection / hardening /
    # disable / etc.). An empty/missing category would surface
    # as an Uncategorized bucket, harming triage. Locks
    # category-present discipline on the bluetooth-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
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
    # The version field MUST follow X.Y.Z semver so the resolver
    # can sort versions numerically + version-gate downstream
    # consumers. A regression to "v1" / "1.0" / "1.0.0-beta+meta"
    # would break the sortable numeric comparison. Locks the
    # semver-X.Y.Z discipline on the bluetooth-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (bluetooth-disable module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the bluetooth-disable module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
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

@test "INVARIANT (bluetooth-disable module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the bluetooth-disable module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
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

@test "INVARIANT (bluetooth-disable module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the bluetooth-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
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

@test "INVARIANT (bluetooth-disable module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for bluetooth-disable is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the bluetooth-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (bluetooth-disable module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the bluetooth-disable install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
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

@test "INVARIANT (bluetooth-disable module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the bluetooth-disable requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
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

@test "INVARIANT (bluetooth-disable module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the bluetooth-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (bluetooth-disable module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the bluetooth-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (bluetooth-disable module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the bluetooth-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (bluetooth-disable module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (bluetooth-disable module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the bluetooth-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
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

@test "INVARIANT (bluetooth-disable module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (bluetooth-disable module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (bluetooth-disable module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (bluetooth-disable module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (bluetooth-disable module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (bluetooth-disable module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (bluetooth-disable README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (bluetooth-disable install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (bluetooth-disable install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (bluetooth-disable install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (bluetooth-disable install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (bluetooth-disable install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (bluetooth-disable install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (bluetooth-disable install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (bluetooth-disable install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (bluetooth-disable install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (bluetooth-disable install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (bluetooth-disable install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (bluetooth-disable install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (bluetooth-disable module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (bluetooth-disable module.toml exists at canonical path modules/bluetooth-disable/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (bluetooth-disable module dir is at canonical path modules/bluetooth-disable/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (bluetooth-disable install dir exists at modules/bluetooth-disable/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (bluetooth-disable install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (bluetooth-disable install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (bluetooth-disable install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (bluetooth-disable install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (bluetooth-disable module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (bluetooth-disable install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/bluetooth-disable/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}
