#!/usr/bin/env bats
# L2 functional suite for usb-storage-mass-disable.
#
# usb-storage-mass-disable blocks USB mass storage at the kernel
# level. Profiles:
#   blocked → modprobe blacklist usb_storage + uas; also `rmmod`
#             them if currently loaded (immediate enforcement)
#   audited → modprobe install hook that logs every load attempt
#             but doesn't block (visibility-only, useful for
#             baselining what's currently expected)
#
# USB mass storage is a classic data-exfiltration + malware-
# introduction vector. On endpoints that don't legitimately use
# USB sticks, blocking the kernel modules closes the entire class.
#
# CRITICAL INVARIANTS:
#   - blocked profile triggers rmmod for currently-loaded modules
#     (immediate enforcement) — non-DRY only.
#   - audited profile does NOT trigger rmmod (visibility-only).
#   - Idempotent: byte-identical re-install doesn't fire rmmod.
#   - DRY_RUN protects modprobe.d + rmmod.
#
# Uses SELFDEF_MODPROBE_D env-var (already present).
#
# Run with: bats packaging/test/L2-usb-storage-mass-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/lsmod" <<'LSEOF'
#!/usr/bin/env bash
# Emit configured loaded module set.
printf '%s\n' "${LSMOD_OUTPUT:-Module                  Size  Used by}"
exit 0
LSEOF
    chmod +x "${BIN}/lsmod"
    cat > "${BIN}/rmmod" <<'RMEOF'
#!/usr/bin/env bash
printf 'rmmod %s\n' "$*" >> "${RMMOD_LOG}"
exit 0
RMEOF
    chmod +x "${BIN}/rmmod"
    export RMMOD_LOG="${TMP}/rmmod.log"
    : > "${RMMOD_LOG}"
    CONF="${TMP}/usb-storage-mass-disable.toml"
    MODPROBE_D="${TMP}/modprobe.d"
    mkdir -p "${MODPROBE_D}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    RMMOD_LOG="${RMMOD_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_USB_DISABLE_CONFIG="${CONF}" \
    SELFDEF_MODPROBE_D="${MODPROBE_D}" \
    LSMOD_OUTPUT="${LSMOD_OUTPUT:-Module                  Size  Used by}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_USB_DISABLE_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_USB_DISABLE_CONFIG="${SELFDEF_USB_DISABLE_CONFIG}" \
        SELFDEF_MODPROBE_D="${MODPROBE_D}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_USB_DISABLE_CONFIG="${CONF}" \
        SELFDEF_MODPROBE_D="${MODPROBE_D}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be blocked|audited"* ]]
}

@test "blocked profile installs the blocked modprobe drop-in" {
    write_config "blocked"
    run_wd
    [ -f "${MODPROBE_D}/50-selfdef-usb-storage.conf" ]
    [ "$(stat -c '%a' "${MODPROBE_D}/50-selfdef-usb-storage.conf")" = "644" ]
}

@test "audited profile installs the audited modprobe drop-in" {
    write_config "audited"
    run_wd
    [ -f "${MODPROBE_D}/50-selfdef-usb-storage.conf" ]
}

@test "INVARIANT: blocked profile + module currently loaded → rmmod fires (immediate enforcement)" {
    write_config "blocked"
    # lsmod emits usb_storage as currently loaded.
    LSMOD_OUTPUT='Module                  Size  Used by
usb_storage            73728  0
uas                    24576  0' run_wd
    grep -q 'rmmod usb_storage' "${RMMOD_LOG}"
    grep -q 'rmmod uas' "${RMMOD_LOG}"
}

@test "INVARIANT: blocked profile + module NOT loaded → NO rmmod fired" {
    write_config "blocked"
    LSMOD_OUTPUT='Module                  Size  Used by' run_wd
    ! grep -q 'rmmod' "${RMMOD_LOG}"
}

@test "INVARIANT: audited profile does NOT trigger rmmod even if loaded (visibility-only)" {
    write_config "audited"
    LSMOD_OUTPUT='Module                  Size  Used by
usb_storage            73728  0' run_wd
    # audited is visibility-only — no rmmod even with module loaded.
    ! grep -q 'rmmod' "${RMMOD_LOG}"
}

@test "INVARIANT: DRY_RUN does not install drop-in or fire rmmod" {
    write_config "blocked"
    LSMOD_OUTPUT='Module                  Size  Used by
usb_storage            73728  0' DRY_RUN=1 run_wd
    ! [ -f "${MODPROBE_D}/50-selfdef-usb-storage.conf" ]
    ! grep -q 'rmmod' "${RMMOD_LOG}"
}

@test "default profile is blocked (no profile key — the secure default)" {
    : > "${CONF}"
    run_wd
    [ -f "${MODPROBE_D}/50-selfdef-usb-storage.conf" ]
    cmp -s modules/usb-storage-mass-disable/configs/blocked.conf "${MODPROBE_D}/50-selfdef-usb-storage.conf"
}

@test "INVARIANT (blocked drop-in covers BOTH usb_storage + uas modules)" {
    write_config "blocked"
    run_wd
    grep -qE '(blacklist|install) usb_storage' "${MODPROBE_D}/50-selfdef-usb-storage.conf"
    grep -qE '(blacklist|install) uas' "${MODPROBE_D}/50-selfdef-usb-storage.conf"
}

@test "INVARIANT (audited drop-in content differs from blocked — audited logs, blocked denies)" {
    write_config "audited"
    run_wd
    sha_a="$(sha256sum "${MODPROBE_D}/50-selfdef-usb-storage.conf" | awk '{print $1}')"
    write_config "blocked"
    run_wd
    sha_b="$(sha256sum "${MODPROBE_D}/50-selfdef-usb-storage.conf" | awk '{print $1}')"
    [ "${sha_a}" != "${sha_b}" ]
}

@test "INVARIANT (profile transition audited → blocked): rewrites drop-in + fires rmmod on loaded modules" {
    write_config "audited"
    LSMOD_OUTPUT='Module                  Size  Used by
usb_storage            73728  0' run_wd
    : > "${RMMOD_LOG}"
    write_config "blocked"
    LSMOD_OUTPUT='Module                  Size  Used by
usb_storage            73728  0' run_wd
    grep -q 'rmmod usb_storage' "${RMMOD_LOG}"
}

@test "INVARIANT (idempotent mtime): byte-identical re-install preserves drop-in mtime" {
    write_config "blocked"
    run_wd
    mtime_before="$(stat -c '%Y' "${MODPROBE_D}/50-selfdef-usb-storage.conf")"
    sleep 1
    LSMOD_OUTPUT='Module                  Size  Used by' run_wd
    mtime_after="$(stat -c '%Y' "${MODPROBE_D}/50-selfdef-usb-storage.conf")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT (no render-timestamp in drop-in): defeats cmp -s idempotency guard" {
    write_config "blocked"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${MODPROBE_D}/50-selfdef-usb-storage.conf"
}

@test "INVARIANT (blocked drop-in carries selfdef-identifier header — operator audit trail + uninstall identification)" {
    # The drop-in carries '# selfdef usb-storage-mass-disable —
    # <profile>' as its first-line tracker (per configs/<profile>
    # .conf source). Locks the marker shape so uninstall +
    # tracking work.
    write_config "blocked"
    run_wd
    grep -qE '^# selfdef usb-storage-mass-disable' "${MODPROBE_D}/50-selfdef-usb-storage.conf"
}

@test "INVARIANT (audited drop-in carries selfdef-identifier header too — both profiles share ownership signal)" {
    write_config "audited"
    run_wd
    grep -qE '^# selfdef usb-storage-mass-disable' "${MODPROBE_D}/50-selfdef-usb-storage.conf"
}

@test "INVARIANT (drop-in re-arm after operator out-of-band deletion: re-creates drop-in)" {
    write_config "blocked"
    run_wd
    [ -f "${MODPROBE_D}/50-selfdef-usb-storage.conf" ]
    rm -f "${MODPROBE_D}/50-selfdef-usb-storage.conf"
    LSMOD_OUTPUT='Module                  Size  Used by' run_wd
    [ -f "${MODPROBE_D}/50-selfdef-usb-storage.conf" ]
    grep -qE '(blacklist|install) usb_storage' "${MODPROBE_D}/50-selfdef-usb-storage.conf"
}

@test "INVARIANT (no phantom rmmod: rmmod called ONLY for modules in lsmod, not blindly)" {
    # Lock that rmmod is gated on lsmod presence — calling rmmod
    # on absent modules would emit benign errors that pollute the
    # log and could mask real issues.
    write_config "blocked"
    LSMOD_OUTPUT='Module                  Size  Used by
usb_storage            73728  0' run_wd
    # usb_storage IS loaded → rmmod fired.
    grep -q 'rmmod usb_storage' "${RMMOD_LOG}"
    # uas NOT loaded → rmmod NOT fired for uas.
    ! grep -q 'rmmod uas' "${RMMOD_LOG}"
}

@test "INVARIANT (emit_status JSON: status=ok + profile + loaded-module-count surfaced for dashboard)" {
    write_config "blocked"
    output="$(LSMOD_OUTPUT='Module                  Size  Used by
usb_storage            73728  0
uas                    24576  0' run_wd 2>&1)"
    [[ "${output}" == *'"module":"usb-storage-mass-disable"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=blocked'* ]]
}

@test "INVARIANT (profile downgrade blocked → audited: rewrites drop-in + does NOT fire rmmod — bidirectional contract)" {
    # Sister to the audited → blocked transition test (which fires
    # rmmod). The reverse direction is operator-loosening; must
    # rewrite content but MUST NOT fire rmmod (audited is
    # visibility-only). Locks the bidirectional contract.
    write_config "blocked"
    LSMOD_OUTPUT='Module                  Size  Used by' run_wd
    : > "${RMMOD_LOG}"
    write_config "audited"
    LSMOD_OUTPUT='Module                  Size  Used by
usb_storage            73728  0' run_wd
    grep -qE '^# selfdef usb-storage-mass-disable' "${MODPROBE_D}/50-selfdef-usb-storage.conf"
    # audited NEVER fires rmmod regardless of transition direction.
    ! grep -q 'rmmod' "${RMMOD_LOG}"
}

@test "INVARIANT (audited drop-in mentions logging mechanism — install hook or audit token)" {
    # The audited drop-in's content must materially differ from
    # blocked — it must wire the modprobe install hook so kernel
    # logs every load attempt. Lock that the audited content
    # contains a recognizable audit/log token, not just a blank
    # placeholder.
    write_config "audited"
    run_wd
    grep -qE 'install|logger|audit|log' "${MODPROBE_D}/50-selfdef-usb-storage.conf"
}

@test "INVARIANT (rmmod failures non-fatal: blocked profile completes apply even if rmmod returns error)" {
    # On real hosts, a loaded module may have in-use references
    # (rmmod -f required). Failure of rmmod MUST NOT bubble up as
    # apply failure — the modprobe.d blacklist is the load-bearing
    # next-boot enforcement; rmmod is best-effort immediate.
    cat > "${BIN}/rmmod" <<'RMEOF'
#!/usr/bin/env bash
printf 'rmmod %s\n' "$*" >> "${RMMOD_LOG}"
exit 1
RMEOF
    chmod +x "${BIN}/rmmod"
    write_config "blocked"
    LSMOD_OUTPUT='Module                  Size  Used by
usb_storage            73728  0' run_wd
    # Drop-in still landed even though rmmod failed.
    [ -f "${MODPROBE_D}/50-selfdef-usb-storage.conf" ]
    grep -qE '(blacklist|install) usb_storage' "${MODPROBE_D}/50-selfdef-usb-storage.conf"
}

@test "INVARIANT (blocked profile covers BOTH usb_storage AND uas — full mass-storage class coverage)" {
    # Sister to many other watchdog/installer's multi-axis coverage
    # INVARIANT across the brain. USB Attached SCSI (uas) is the
    # newer-generation mass-storage transport, used by USB 3.0+
    # thumb drives that negotiate UAS instead of legacy BOT. An
    # attacker plugging in a UAS-only thumb drive would bypass a
    # usb_storage-only blacklist. Lock the complete class coverage:
    # blocked profile MUST blacklist BOTH usb_storage AND uas.
    # T1052 (Hardware Additions) data-exfil + T1091 (Replication
    # Through Removable Media) malware-introduction primitives both
    # close.
    write_config "blocked"
    run_wd
    grep -qE '(blacklist|install) usb_storage' "${MODPROBE_D}/50-selfdef-usb-storage.conf"
    grep -qE '(blacklist|install) uas' "${MODPROBE_D}/50-selfdef-usb-storage.conf"
}

@test "INVARIANT (DRY_RUN does not fire rmmod or write the modprobe drop-in)" {
    # Sister to many other installer module's DRY_RUN INVARIANT
    # across the brain. The usb-storage-mass-disable DRY_RUN
    # path MUST be a no-op against live kernel state + live
    # filesystem — operator using --dry-run to preview expects
    # ZERO mutations. Locks the dry-run side-effect-freedom
    # contract so a regression that fires rmmod or writes the
    # modprobe drop-in through DRY_RUN would be caught.
    write_config "blocked"
    LSMOD_OUTPUT='Module                  Size  Used by
usb_storage            73728  0' DRY_RUN=1 run_wd
    ! [ -f "${MODPROBE_D}/50-selfdef-usb-storage.conf" ]
    ! [ -s "${RMMOD_LOG}" ]
}

@test "INVARIANT (modprobe drop-in is chmod 0644 — system-config convention)" {
    # Sister to brain-wide chmod 0644 INVARIANTs. The modprobe
    # drop-in lands at /etc/modprobe.d/50-selfdef-usb-storage.conf
    # and must be world-readable (modprobe at boot reads it) and
    # root-write-only (any user rewrite would re-enable USB-storage
    # autoload).
    write_config "blocked"
    run_wd
    [ -f "${MODPROBE_D}/50-selfdef-usb-storage.conf" ]
    [ "$(stat -c '%a' "${MODPROBE_D}/50-selfdef-usb-storage.conf")" = "644" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on usb-storage-mass-disable
    # installer surface across modprobe-drop-in + rmmod phases.
    write_config "blocked"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"usb-storage-mass-disable"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (header-marker discipline: drop-in carries 'selfdef' self-identifying header — head-grep stale-cleanup discipline)" {
    # Sister to brain-wide header-marker discipline INVARIANTs
    # across L2 drop-in suites. The usb-storage-mass-disable
    # drop-in under /etc/modprobe.d/50-selfdef-usb-storage.conf
    # MUST carry a comment marker identifying it as selfdef-
    # managed so a stale-cleanup head -2 grep at uninstall time
    # can identify which files selfdef owns vs which is
    # operator-original. Without a marker, a subsequent
    # uninstaller could not tell apart operator baseline modprobe
    # rules from selfdef-injected blacklist directives — risking
    # accidental rollback of operator changes. Locks marker-
    # discipline on the usb-storage modprobe.d substrate.
    write_config "blocked"
    run_wd
    dropin="${MODPROBE_D}/50-selfdef-usb-storage.conf"
    [ -f "${dropin}" ]
    grep -qE '^#.*(selfdef|usb-storage-mass-disable|managed)' "${dropin}"
}

@test "INVARIANT (no auto-uninstall: usb-storage-mass-disable NEVER emits package-remove commands)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The usb-storage-mass-disable installer writes
    # a modprobe.d blacklist + may fire rmmod usb_storage but
    # MUST NEVER emit shell commands that uninstall kernel-mod
    # related packages (apt/dpkg/dnf/rpm/yum remove|purge|
    # uninstall linux-modules|kmod|systemd). Auto-removal would
    # be catastrophic at the kernel-substrate level. Locks
    # anti-package-removal contract on the usb-storage-mass-
    # disable substrate.
    write_config "blocked"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(linux-modules|kmod|systemd)'
    dropin="${MODPROBE_D}/50-selfdef-usb-storage.conf"
    [ ! -f "${dropin}" ] || ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${dropin}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. usb-storage-mass-disable manifest declares install
    # + profile gating the resolver enforces; malformed manifest
    # wedges the /etc/modprobe.d usb-storage disable drop-in.
    # Python's tomllib is the canonical parser. Locks anti-
    # malformed-manifest on the usb-storage-mass-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'usb-storage-mass-disable', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: usb-storage-mass-disable installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # usb-storage-mass-disable writes its own drop-in/config; it MUST NEVER
    # rm/find-delete operator-pre-existing entries not owned by
    # THIS module. Locks no-auto-delete on the usb-storage-mass-disable
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(sysctl\.conf|sysctl\.d|fstab|fstab\.d|systemd|profile\.d|login\.defs|apt|modprobe\.d|usbguard)[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(sysctl\.d|fstab\.d|systemd|profile\.d|apt|modprobe\.d|usbguard).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # usb-storage-mass-disable install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the usb-storage-mass-disable lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the usb-storage-mass-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
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
    # the usb-storage-mass-disable requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
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
    # usb-storage-mass-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
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
    # usb-storage-mass-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
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
    # Locks semver-X.Y.Z discipline on the usb-storage-mass-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}
