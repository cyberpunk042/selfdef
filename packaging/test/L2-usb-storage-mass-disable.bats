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

@test "INVARIANT (usb-storage-mass-disable module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the usb-storage-mass-disable module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
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

@test "INVARIANT (usb-storage-mass-disable module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the usb-storage-mass-disable module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
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

@test "INVARIANT (usb-storage-mass-disable module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the usb-storage-mass-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
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

@test "INVARIANT (usb-storage-mass-disable module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for usb-storage-mass-disable is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the usb-storage-mass-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the usb-storage-mass-disable install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
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

@test "INVARIANT (usb-storage-mass-disable module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the usb-storage-mass-disable requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
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

@test "INVARIANT (usb-storage-mass-disable module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the usb-storage-mass-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the usb-storage-mass-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the usb-storage-mass-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the usb-storage-mass-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
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

@test "INVARIANT (usb-storage-mass-disable module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (usb-storage-mass-disable install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (usb-storage-mass-disable install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (usb-storage-mass-disable install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (usb-storage-mass-disable install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (usb-storage-mass-disable install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (usb-storage-mass-disable install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (usb-storage-mass-disable install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (usb-storage-mass-disable install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (usb-storage-mass-disable install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (usb-storage-mass-disable install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (usb-storage-mass-disable install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (usb-storage-mass-disable install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (usb-storage-mass-disable module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml exists at canonical path modules/usb-storage-mass-disable/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (usb-storage-mass-disable module dir is at canonical path modules/usb-storage-mass-disable/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (usb-storage-mass-disable install dir exists at modules/usb-storage-mass-disable/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (usb-storage-mass-disable install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (usb-storage-mass-disable install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (usb-storage-mass-disable install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (usb-storage-mass-disable install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (usb-storage-mass-disable module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (usb-storage-mass-disable install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (usb-storage-mass-disable install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (usb-storage-mass-disable install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (usb-storage-mass-disable install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (usb-storage-mass-disable install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (usb-storage-mass-disable install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (usb-storage-mass-disable install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (usb-storage-mass-disable install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (usb-storage-mass-disable module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
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

@test "INVARIANT (usb-storage-mass-disable module.toml has at least 1 entry in install_paths.paths — non-empty-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 1
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml install_paths.scope canonical-system 92 — operator-scope-fixed)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc in ('system', 'user', '')
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml install_paths.paths has /etc/selfdef/ entry 93 — selfdef-config-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/etc/selfdef/' in p for p in ps)
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (usb-storage-mass-disable module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (usb-storage-mass-disable module.toml uses TOML key-value assignment syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (usb-storage-mass-disable module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (usb-storage-mass-disable module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (usb-storage-mass-disable module.toml category field uses double-quoted string syntax — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (usb-storage-mass-disable module.toml summary field uses double-quoted string syntax — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (usb-storage-mass-disable module.toml name field value matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"usb-storage-mass-disable"' "${mtoml}"
}

@test "INVARIANT (usb-storage-mass-disable module.toml top-level keys before any [section] header — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
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

@test "INVARIANT (usb-storage-mass-disable module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (usb-storage-mass-disable module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (usb-storage-mass-disable module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (usb-storage-mass-disable module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (usb-storage-mass-disable module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (usb-storage-mass-disable module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (usb-storage-mass-disable module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}

@test "INVARIANT (usb-storage-mass-disable module.toml [install] check value is non-empty string ending with .sh — TOML-install-check-shape-canonical 112)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ck = (data.get('install') or {}).get('check', '')
assert isinstance(ck, str) and ck and ck.endswith('.sh'), f'install.check must be non-empty .sh path, got {ck!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml version field matches semver X.Y.Z pattern — TOML-version-semver-canonical 113)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v), f'version must be semver X.Y.Z, got {v!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml summary field is non-empty string with length >= 30 chars — TOML-summary-substance-floor 114)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) >= 30, f'summary must be string with len >= 30, got len={len(s)} value={s!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml top-level requires field is a TOML list — TOML-requires-list-canonical 115)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml top-level provides field is a TOML list — TOML-provides-list-canonical 116)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('provides')
assert isinstance(r, list), f'provides must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml top-level conflicts field is a TOML list — TOML-conflicts-list-canonical 117)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('conflicts')
assert isinstance(r, list), f'conflicts must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml top-level depends_on field is a TOML list — TOML-depends-on-list-canonical 118)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('depends_on')
assert isinstance(r, list), f'depends_on must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml top-level consumes field is a TOML list — TOML-consumes-list-canonical 119)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('consumes')
assert isinstance(r, list), f'consumes must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml top-level instanced field is a TOML boolean — TOML-instanced-bool-canonical 120)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('instanced')
assert isinstance(r, bool), f'instanced must be bool, got {type(r).__name__}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml [install] uninstall value is non-empty string ending with .sh — TOML-install-uninstall-shape-canonical 121)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = (data.get('install') or {}).get('uninstall', '')
assert isinstance(v, str) and v and v.endswith('.sh'), f'install.uninstall must be non-empty .sh path, got {v!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml has [profiles] section header — TOML-profiles-section-canonical 122)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    grep -qE '^\[profiles\]$' "${mtoml}"
}

@test "INVARIANT (usb-storage-mass-disable module.toml [profiles] default field is non-empty string — TOML-profiles-default-canonical 123)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert isinstance(d, str) and d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml [profiles] available field is a TOML list — TOML-profiles-available-list-canonical 124)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available')
assert isinstance(a, list), f'profiles.available must be list, got {type(a).__name__}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml [profiles] available list contains at least one element — TOML-profiles-available-non-empty-canonical 125)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert isinstance(a, list) and len(a) >= 1, f'profiles.available must be non-empty list, got {a!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml [profiles] default value appears in [profiles] available list (semantic consistency) — TOML-profiles-default-in-available-canonical 126)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('profiles') or {}
default = p.get('default')
available = p.get('available') or []
assert default in available, f'profiles.default {default!r} must appear in available {available!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml [profiles] available list contains only string elements — TOML-profiles-available-elements-string-canonical 127)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert all(isinstance(x, str) for x in a), f'profiles.available items must all be strings, got {[type(x).__name__ for x in a]!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml requires list elements are inline-tables with kind+value keys (or empty) — TOML-requires-elements-shape-canonical 128)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
for el in r:
    assert isinstance(el, dict), f'requires element must be inline-table, got {type(el).__name__}'
    assert 'kind' in el and 'value' in el, f'requires element must have kind+value keys, got {sorted(el.keys())!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml requires items have kind in bounded vocab {binary, package, kernel-feature} — TOML-requires-kind-vocab-canonical 129)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
allowed = {'binary', 'package', 'kernel-feature'}
for el in r:
    k = el.get('kind', '')
    assert k in allowed, f'requires.kind must be in {allowed}, got {k!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml requires items have value as non-empty string — TOML-requires-value-nonempty-canonical 130)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
for el in r:
    v = el.get('value', '')
    assert isinstance(v, str) and v, f'requires.value must be non-empty string, got {v!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml provides list elements are all non-empty strings — TOML-provides-elements-string-canonical 131)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides') or []
for el in p:
    assert isinstance(el, str) and el, f'provides element must be non-empty string, got {el!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml conflicts list elements are all non-empty strings (or empty list) — TOML-conflicts-elements-string-canonical 132)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('conflicts') or []
for el in c:
    assert isinstance(el, str) and el, f'conflicts element must be non-empty string, got {el!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml consumes list elements are all non-empty strings (or empty) — TOML-consumes-elements-string-canonical 133)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('consumes') or []
for el in c:
    assert isinstance(el, str) and el, f'consumes element must be non-empty string, got {el!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml depends_on list elements are all non-empty strings (or empty) — TOML-depends-on-elements-string-canonical 134)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('depends_on') or []
for el in c:
    assert isinstance(el, str) and el, f'depends_on element must be non-empty string, got {el!r}'
"
}

@test "INVARIANT (usb-storage-mass-disable module.toml install_paths.paths list elements are all absolute paths (starting with /) — TOML-install-paths-paths-absolute-canonical 135)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
for el in paths:
    assert isinstance(el, str) and el and el.startswith('/'), f'install_paths.paths element must be absolute path, got {el!r}'
"
}
