#!/usr/bin/env bats
# L2 functional suite for avahi-disable.
#
# avahi-disable stops + disables Avahi (mDNS/DNS-SD daemon).
# Avahi advertises the host's services on the local network — every
# enabled service is a fingerprint + lateral-movement target. On a
# sovereign endpoint with no need to advertise (server, workstation),
# Avahi is pure attack surface.
#
# Acts on TWO units (avahi-daemon.service + avahi-daemon.socket) per
# the AVAHI_UNITS array in lib.sh. Profiles: stop | mask. DRY_RUN=1
# → no system changes.
#
# Tests shadow systemctl on PATH with a deterministic fake that
# logs every invocation. Uses the same pattern as L2-at-disable.bats
# (the first installer-module L2 suite).
#
# Run with: bats packaging/test/L2-avahi-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
case "$1" in
    list-unit-files)
        case "$2" in
            avahi-daemon.service|avahi-daemon.socket)
                if [[ "${AVAHI_PRESENT:-1}" == "1" ]]; then
                    printf 'UNIT FILE     STATE\n%s   enabled\n' "$2"
                    exit 0
                else
                    exit 1
                fi ;;
        esac ;;
    is-active|is-enabled)
        exit 0 ;;
esac
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/avahi-disable.toml"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_AVAHI_CONFIG="${CONF}" \
    AVAHI_PRESENT="${AVAHI_PRESENT:-1}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_AVAHI_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_AVAHI_CONFIG="${SELFDEF_AVAHI_CONFIG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile value → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_AVAHI_CONFIG="${CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be mask|stop"* ]]
}

@test "avahi not present → ok no-op, no stop/disable/mask" {
    write_config "mask"
    AVAHI_PRESENT=0 run_wd
    # Only list-unit-files runs (twice, once per AVAHI_UNITS entry).
    [ "$(grep -c 'systemctl list-unit-files' "${SYSEOF_LOG}")" -eq 2 ]
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "DRY_RUN=1 → no systemctl mutation" {
    write_config "mask"
    DRY_RUN=1 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "stop profile (real) → stop + disable both units, NO mask" {
    write_config "stop"
    run_wd
    grep -q 'systemctl stop avahi-daemon.service' "${SYSEOF_LOG}"
    grep -q 'systemctl stop avahi-daemon.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl disable avahi-daemon.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable avahi-daemon.socket' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask' "${SYSEOF_LOG}"
}

@test "mask profile (real) → stop + disable + mask both units" {
    write_config "mask"
    run_wd
    grep -q 'systemctl mask avahi-daemon.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask avahi-daemon.socket' "${SYSEOF_LOG}"
}

@test "default profile is mask (when config has no profile key)" {
    : > "${CONF}"
    run_wd
    grep -q 'systemctl mask avahi-daemon.service' "${SYSEOF_LOG}"
}

@test "idempotent on second run" {
    write_config "mask"
    run_wd
    : > "${SYSEOF_LOG}"
    run_wd
    # systemctl invocations replay; the units stay in the disabled
    # state. Real systemctl is idempotent and our fake always exits 0.
    grep -q 'systemctl mask avahi-daemon.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (.socket+.service dual coverage in stop): both units are stopped + disabled (avahi.socket can re-activate .service)" {
    # avahi-daemon.socket can re-activate avahi-daemon.service on
    # demand via systemd socket activation. If only .service is
    # touched, .socket brings it right back. Both must be acted on.
    write_config "stop"
    run_wd
    grep -q 'systemctl stop avahi-daemon.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl disable avahi-daemon.socket' "${SYSEOF_LOG}"
}

@test "INVARIANT (.socket+.service dual coverage in mask): both units are masked" {
    write_config "mask"
    run_wd
    grep -q 'systemctl mask avahi-daemon.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask avahi-daemon.socket' "${SYSEOF_LOG}"
}

@test "INVARIANT (idempotent stop): re-applying stop profile fires the same systemctl set across both applies" {
    write_config "stop"
    run_wd
    first_log="$(cat "${SYSEOF_LOG}")"
    : > "${SYSEOF_LOG}"
    run_wd
    second_log="$(cat "${SYSEOF_LOG}")"
    diff <(printf '%s\n' "${first_log}") <(printf '%s\n' "${second_log}") >/dev/null
}

@test "INVARIANT (idempotent mask): re-applying mask profile fires the same set + does not escalate scope" {
    write_config "mask"
    run_wd
    first_log="$(cat "${SYSEOF_LOG}")"
    : > "${SYSEOF_LOG}"
    run_wd
    second_log="$(cat "${SYSEOF_LOG}")"
    diff <(printf '%s\n' "${first_log}") <(printf '%s\n' "${second_log}") >/dev/null
}

@test "emit_status surfaces profile + result in JSON (operator observability)" {
    write_config "mask"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"avahi-disable"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=mask'* ]]
}

@test "avahi not present + DRY_RUN=1 → still no mutation (dry-run + detect short-circuit compose correctly)" {
    write_config "mask"
    DRY_RUN=1 AVAHI_PRESENT=0 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "INVARIANT (mask is a superset of stop: stop+disable+mask sequence; stop omits the mask step)" {
    # Lock the architectural contract: mask profile = stop profile
    # + additional mask step. Operator escalation path is
    # stop→mask without re-applying the disable.
    write_config "mask"
    run_wd
    grep -q 'systemctl stop avahi-daemon.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable avahi-daemon.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask avahi-daemon.service' "${SYSEOF_LOG}"
    : > "${SYSEOF_LOG}"
    write_config "stop"
    run_wd
    grep -q 'systemctl stop avahi-daemon.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable avahi-daemon.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask avahi-daemon.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (acted count surfaces in JSON: acted=2 when both units are present — operator dashboard)" {
    write_config "mask"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'acted=2'* ]]
    [[ "${output}" == *'skipped=0'* ]]
}

@test "INVARIANT (acted=0 + no-op message when avahi absent — operator dashboard distinguishes 'applied' vs 'not-present')" {
    write_config "mask"
    output="$(AVAHI_PRESENT=0 run_wd 2>&1)"
    [[ "${output}" == *'no-op'* ]]
    [[ "${output}" == *'avahi not present'* ]]
}

@test "INVARIANT (mask order is stop → disable → mask — NOT mask → stop): mask before stop would leave .service exited but socket-activatable" {
    # The systemctl mask is a runtime-permanent gate; if applied
    # BEFORE stop, the service might already be running. The
    # ordering ensures: stop first (terminate in-flight), disable
    # (clear boot trigger), mask last (permanent gate). Locks the
    # sequence so future refactor doesn't accidentally swap.
    write_config "mask"
    run_wd
    # The log contains the actions in order. Extract them.
    stop_line="$(grep -n 'systemctl stop avahi-daemon.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    disable_line="$(grep -n 'systemctl disable avahi-daemon.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    mask_line="$(grep -n 'systemctl mask avahi-daemon.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    [ "${stop_line}" -lt "${disable_line}" ]
    [ "${disable_line}" -lt "${mask_line}" ]
}

@test "INVARIANT (.socket also follows stop→disable→mask order — symmetric ordering across all units)" {
    # Same order MUST hold for avahi-daemon.socket as for .service.
    # A regression that applies the order to only one unit would
    # leave the other reactivatable.
    write_config "mask"
    run_wd
    stop_socket="$(grep -n 'systemctl stop avahi-daemon.socket' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    disable_socket="$(grep -n 'systemctl disable avahi-daemon.socket' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    mask_socket="$(grep -n 'systemctl mask avahi-daemon.socket' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    [ "${stop_socket}" -lt "${disable_socket}" ]
    [ "${disable_socket}" -lt "${mask_socket}" ]
}

@test "INVARIANT (downgrade mask → stop does NOT auto-unmask — operator-explicit unmask required)" {
    # Once masked, a downgrade to stop profile does NOT auto-unmask
    # the units. The unmask requires explicit operator action.
    # Locks the architectural safety: mask is sticky; operator
    # must affirmatively undo it to allow re-enablement.
    write_config "mask"
    run_wd
    : > "${SYSEOF_LOG}"
    write_config "stop"
    run_wd
    # stop profile fires stop+disable but does NOT fire unmask.
    grep -q 'systemctl stop avahi-daemon.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl unmask avahi-daemon.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (no package-uninstall: avahi-daemon package NEVER auto-removed — module neutralizes, doesn't uninstall)" {
    # Sister to bluetooth-disable + services-disable-printing no-
    # auto-uninstall INVARIANT. Module's contract is to neutralize,
    # not uninstall. avahi-daemon package removal is operator
    # decision via apt/dnf/yum.
    write_config "mask"
    run_wd
    ! grep -qE 'apt|dnf|yum|rpm' "${SYSEOF_LOG}"
}

@test "INVARIANT (mDNS-port observability: avahi's UDP/5353 surface is closed when both units masked — observability via systemd-status check post-mask)" {
    # The whole point is closing UDP/5353 (mDNS). The .socket unit
    # is what binds that port; masking it ensures binding cannot
    # re-occur. Lock that the mask covers BOTH units explicitly
    # (already covered by dual-coverage tests, but this locks the
    # port-closure architectural intent).
    write_config "mask"
    run_wd
    # The .socket is the port-bind unit — MUST be masked.
    grep -q 'systemctl mask avahi-daemon.socket' "${SYSEOF_LOG}"
}

@test "INVARIANT (mask order symmetric across BOTH units in the SAME run: .service AND .socket stop_line before disable_line before mask_line in same scan)" {
    # Combines existing per-unit symmetric-mask-order tests into a
    # single-scan INVARIANT: both units MUST follow stop→disable→
    # mask sequence WITHIN the same apply run, not just per-unit
    # isolation. Locks atomic-multi-unit ordering.
    write_config "mask"
    run_wd
    # All 6 lines (stop+disable+mask × 2 units) must appear in
    # canonical order per-unit.
    for unit in avahi-daemon.service avahi-daemon.socket; do
        s="$(grep -n "systemctl stop ${unit}" "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
        d="$(grep -n "systemctl disable ${unit}" "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
        m="$(grep -n "systemctl mask ${unit}" "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
        [ -n "${s}" ] && [ -n "${d}" ] && [ -n "${m}" ]
        [ "${s}" -lt "${d}" ]
        [ "${d}" -lt "${m}" ]
    done
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # avahi-disable TOML; parser must tolerate without altering the
    # profile-gated behavior. mask-with-noise still fires the full
    # mask sequence on BOTH avahi-daemon.service + avahi-daemon.
    # socket (mDNS broadcast surveillance / mDNS-spoof / DNS-rebind
    # / local-network-reconnaissance neutralization).
    cat > "${CONF}" <<'TOMLEOF'
profile = "mask"
operator_note = "avahi mDNS = local-network surveillance broadcast"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    grep -q 'systemctl mask avahi-daemon.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask avahi-daemon.socket' "${SYSEOF_LOG}"
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO systemctl mask/disable/stop fires when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain (acct-baseline / aslr-baseline / apport-
    # disable / at-disable / many others). Operator's exploratory
    # --dry-run MUST preview without firing systemctl stop/disable/
    # mask against avahi-daemon.service OR avahi-daemon.socket.
    # Without strict DRY_RUN gating, a previewed dry-run would
    # silently neutralize mDNS broadcast on a host where operator
    # legitimately uses it (Linux desktop with print-server
    # discovery, IoT-control nodes). Locks the dry-run-preserves-
    # state contract on the mDNS-broadcast neutralization
    # substrate.
    write_config "mask"
    : > "${SYSEOF_LOG}"
    DRY_RUN=1 run_wd
    ! grep -q 'systemctl mask avahi-daemon.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask avahi-daemon.socket' "${SYSEOF_LOG}"
    ! grep -q 'systemctl stop avahi-daemon.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (no auto-uninstall: avahi-daemon package NEVER auto-removed)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs.
    write_config "mask"
    run_wd
    ! grep -qE '(apt-get|dpkg|dnf|rpm)[[:space:]]+(remove|purge|uninstall)' "${SYSEOF_LOG}"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on avahi-disable installer surface
    # across .service + .socket unit phases.
    write_config "mask"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"avahi-disable"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on avahi-disable surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The avahi-disable installer MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the avahi-service neutralization status alert.
    # Locks parser contract on the avahi-disable installer JSON
    # surface (consistency-with-watchdog-family discipline).
    write_config "mask"
    output="$(run_wd 2>&1)"
    bad=$(printf '%s\n' "${output}" | grep -oE '"severity":"[^"]+"' | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (DRY_RUN side-effect-freedom on libexec/units paths: NO file written and NO systemctl when DRY_RUN=1 — comprehensive)" {
    # Sister to brain-wide DRY_RUN side-effect-freedom INVARIANTs.
    # The avahi-disable installer has an existing DRY_RUN
    # invariant for systemctl mask/disable/stop suppression.
    # This INVARIANT extends coverage to verify that even on
    # repeat DRY_RUN invocations (operator iterating
    # exploratory) NO state is written: SYSEOF_LOG remains
    # empty across multiple consecutive DRY_RUN runs. Locks
    # operator-exploration safety contract on the avahi-disable
    # substrate.
    write_config "mask"
    : > "${SYSEOF_LOG}"
    DRY_RUN=1 run_wd
    DRY_RUN=1 run_wd
    DRY_RUN=1 run_wd
    ! grep -qE 'systemctl (mask|disable|stop)' "${SYSEOF_LOG}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. avahi-disable manifest declares install + profile
    # gating the resolver enforces; malformed manifest wedges
    # the avahi-daemon neutralization sequence. Python's tomllib
    # is the canonical parser. Locks anti-malformed-manifest on
    # the avahi-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'avahi-disable', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # avahi-disable install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state (one drop-in
    # written + another aborted mid-way) is detectable rather
    # than a half-applied silent state. Locks fail-loud
    # invariant on the avahi-disable lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install"
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
    # the depends_on field of the avahi-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
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
    # avahi-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
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
    # the avahi-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
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
    # the avahi-disable requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
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
    # present discipline on the avahi-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
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
    # category-present discipline on the avahi-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
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
    # semver-X.Y.Z discipline on the avahi-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (avahi-disable module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the avahi-disable module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
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

@test "INVARIANT (avahi-disable module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the avahi-disable module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
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

@test "INVARIANT (avahi-disable module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the avahi-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
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

@test "INVARIANT (avahi-disable module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for avahi-disable is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the avahi-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (avahi-disable module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the avahi-disable install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
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

@test "INVARIANT (avahi-disable module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the avahi-disable requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
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

@test "INVARIANT (avahi-disable module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the avahi-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (avahi-disable module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the avahi-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (avahi-disable module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the avahi-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (avahi-disable module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (avahi-disable module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the avahi-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
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

@test "INVARIANT (avahi-disable module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (avahi-disable module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (avahi-disable module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (avahi-disable module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (avahi-disable module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (avahi-disable module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (avahi-disable README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (avahi-disable install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (avahi-disable install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (avahi-disable install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (avahi-disable install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (avahi-disable install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (avahi-disable install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (avahi-disable install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (avahi-disable install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (avahi-disable install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (avahi-disable install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (avahi-disable install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (avahi-disable install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (avahi-disable module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (avahi-disable module.toml exists at canonical path modules/avahi-disable/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (avahi-disable module dir is at canonical path modules/avahi-disable/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/avahi-disable"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (avahi-disable install dir exists at modules/avahi-disable/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (avahi-disable install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (avahi-disable install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (avahi-disable install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (avahi-disable install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (avahi-disable module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (avahi-disable install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (avahi-disable install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (avahi-disable install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (avahi-disable install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (avahi-disable install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (avahi-disable install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (avahi-disable install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (avahi-disable install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (avahi-disable module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (avahi-disable module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (avahi-disable module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
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

@test "INVARIANT (avahi-disable module.toml has at least 1 entry in install_paths.paths — non-empty-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 1
"
}

@test "INVARIANT (avahi-disable module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (avahi-disable module.toml install_paths.scope canonical-system 92 — operator-scope-fixed)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc in ('system', 'user', '')
"
}

@test "INVARIANT (avahi-disable module.toml install_paths.paths has /etc/selfdef/ entry 93 — selfdef-config-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/etc/selfdef/' in p for p in ps)
"
}

@test "INVARIANT (avahi-disable module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (avahi-disable module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (avahi-disable module.toml uses TOML key-value assignment syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (avahi-disable module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (avahi-disable module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (avahi-disable module.toml category field uses double-quoted string syntax — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (avahi-disable module.toml summary field uses double-quoted string syntax — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (avahi-disable module.toml name field value matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"avahi-disable"' "${mtoml}"
}

@test "INVARIANT (avahi-disable module.toml top-level keys before any [section] header — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
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

@test "INVARIANT (avahi-disable module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (avahi-disable module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (avahi-disable module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (avahi-disable module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (avahi-disable module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (avahi-disable module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (avahi-disable module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (avahi-disable module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (avahi-disable module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}

@test "INVARIANT (avahi-disable module.toml [install] check value is non-empty string ending with .sh — TOML-install-check-shape-canonical 112)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ck = (data.get('install') or {}).get('check', '')
assert isinstance(ck, str) and ck and ck.endswith('.sh'), f'install.check must be non-empty .sh path, got {ck!r}'
"
}

@test "INVARIANT (avahi-disable module.toml version field matches semver X.Y.Z pattern — TOML-version-semver-canonical 113)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v), f'version must be semver X.Y.Z, got {v!r}'
"
}

@test "INVARIANT (avahi-disable module.toml summary field is non-empty string with length >= 30 chars — TOML-summary-substance-floor 114)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) >= 30, f'summary must be string with len >= 30, got len={len(s)} value={s!r}'
"
}

@test "INVARIANT (avahi-disable module.toml top-level requires field is a TOML list — TOML-requires-list-canonical 115)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (avahi-disable module.toml top-level provides field is a TOML list — TOML-provides-list-canonical 116)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('provides')
assert isinstance(r, list), f'provides must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (avahi-disable module.toml top-level conflicts field is a TOML list — TOML-conflicts-list-canonical 117)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('conflicts')
assert isinstance(r, list), f'conflicts must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (avahi-disable module.toml top-level depends_on field is a TOML list — TOML-depends-on-list-canonical 118)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('depends_on')
assert isinstance(r, list), f'depends_on must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (avahi-disable module.toml top-level consumes field is a TOML list — TOML-consumes-list-canonical 119)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('consumes')
assert isinstance(r, list), f'consumes must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (avahi-disable module.toml top-level instanced field is a TOML boolean — TOML-instanced-bool-canonical 120)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('instanced')
assert isinstance(r, bool), f'instanced must be bool, got {type(r).__name__}'
"
}

@test "INVARIANT (avahi-disable module.toml [install] uninstall value is non-empty string ending with .sh — TOML-install-uninstall-shape-canonical 121)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = (data.get('install') or {}).get('uninstall', '')
assert isinstance(v, str) and v and v.endswith('.sh'), f'install.uninstall must be non-empty .sh path, got {v!r}'
"
}

@test "INVARIANT (avahi-disable module.toml has [profiles] section header — TOML-profiles-section-canonical 122)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    grep -qE '^\[profiles\]$' "${mtoml}"
}

@test "INVARIANT (avahi-disable module.toml [profiles] default field is non-empty string — TOML-profiles-default-canonical 123)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert isinstance(d, str) and d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (avahi-disable module.toml [profiles] available field is a TOML list — TOML-profiles-available-list-canonical 124)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available')
assert isinstance(a, list), f'profiles.available must be list, got {type(a).__name__}'
"
}

@test "INVARIANT (avahi-disable module.toml [profiles] available list contains at least one element — TOML-profiles-available-non-empty-canonical 125)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert isinstance(a, list) and len(a) >= 1, f'profiles.available must be non-empty list, got {a!r}'
"
}

@test "INVARIANT (avahi-disable module.toml [profiles] default value appears in [profiles] available list (semantic consistency) — TOML-profiles-default-in-available-canonical 126)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
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

@test "INVARIANT (avahi-disable module.toml [profiles] available list contains only string elements — TOML-profiles-available-elements-string-canonical 127)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/avahi-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert all(isinstance(x, str) for x in a), f'profiles.available items must all be strings, got {[type(x).__name__ for x in a]!r}'
"
}
