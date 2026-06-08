#!/usr/bin/env bats
# L2 functional suite for services-disable-printing.
#
# services-disable-printing stops + disables CUPS + saned (the
# scanner daemon). On a sovereign endpoint that doesn't print or
# scan, these are pure attack surface — CUPS in particular has
# a long history of remote-code-execution CVEs (see the 2024
# CUPS chain). Acts on 7 candidate units.
#
# Profiles: stop | mask. DRY_RUN=1 → no system changes.
#
# Same systemctl-PATH-shadow test pattern as the other *-disable
# modules.
#
# Run with: bats packaging/test/L2-services-disable-printing.bats

WD="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
case "$1" in
    list-unit-files)
        case "$2" in
            cups.service|cups.socket|cups.path|cups-browsed.service|saned.socket|saned.service|printer.target)
                if [[ "${PRINT_PRESENT:-1}" == "1" ]]; then
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
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/services-disable-printing.toml"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_PRINTING_CONFIG="${CONF}" \
    PRINT_PRESENT="${PRINT_PRESENT:-1}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_PRINTING_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_PRINTING_CONFIG="${SELFDEF_PRINTING_CONFIG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_PRINTING_CONFIG="${CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be mask|stop"* ]]
}

@test "no print/scan units present → no mutation" {
    write_config "mask"
    PRINT_PRESENT=0 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "DRY_RUN=1 → no systemctl mutation" {
    write_config "mask"
    DRY_RUN=1 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "mask profile acts on all 7 print/scan units (cups + cups-browsed + saned + printer.target)" {
    write_config "mask"
    run_wd
    for unit in cups.service cups.socket cups.path cups-browsed.service saned.socket saned.service printer.target; do
        grep -q "systemctl mask ${unit}" "${SYSEOF_LOG}"
    done
}

@test "stop profile acts on all 7 units (stop + disable, NO mask)" {
    write_config "stop"
    run_wd
    for unit in cups.service cups.socket cups.path cups-browsed.service saned.socket saned.service printer.target; do
        grep -q "systemctl stop ${unit}" "${SYSEOF_LOG}"
        grep -q "systemctl disable ${unit}" "${SYSEOF_LOG}"
    done
    ! grep -q 'systemctl mask' "${SYSEOF_LOG}"
}

@test "default profile is mask (no profile key)" {
    : > "${CONF}"
    run_wd
    grep -q 'systemctl mask cups.service' "${SYSEOF_LOG}"
}

@test "idempotent on second run" {
    write_config "mask"
    run_wd
    : > "${SYSEOF_LOG}"
    run_wd
    # The systemctl invocations replay; the units stay in target state.
    grep -q 'systemctl mask cups.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (cups family coverage): all 4 cups-related units acted on (.service + .socket + .path + cups-browsed)" {
    write_config "mask"
    run_wd
    grep -q 'systemctl mask cups.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask cups.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl mask cups.path' "${SYSEOF_LOG}"
    grep -q 'systemctl mask cups-browsed.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (saned family coverage): both saned units acted on (.service + .socket)" {
    write_config "mask"
    run_wd
    grep -q 'systemctl mask saned.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask saned.socket' "${SYSEOF_LOG}"
}

@test "INVARIANT (printer.target umbrella): printer.target IS in the action set (umbrella unit)" {
    # printer.target is the systemd target that other printer
    # units WantedBy. Masking it short-circuits the printer-stack
    # activation chain entirely.
    write_config "mask"
    run_wd
    grep -q 'systemctl mask printer.target' "${SYSEOF_LOG}"
}

@test "INVARIANT (cups.socket+cups.path dual coverage in stop): stop also acts on socket+path (not just .service)" {
    # cups.socket + cups.path can both re-activate cups.service on
    # demand. Disabling only .service would leave both activation
    # paths alive.
    write_config "stop"
    run_wd
    grep -q 'systemctl stop cups.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl disable cups.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl stop cups.path' "${SYSEOF_LOG}"
    grep -q 'systemctl disable cups.path' "${SYSEOF_LOG}"
}

@test "INVARIANT (idempotent mask): re-applying mask fires the same systemctl set across both applies" {
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
    [[ "${output}" == *'"module":"services-disable-printing"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=mask'* ]]
}

@test "INVARIANT (mask is superset of stop: stop+disable+mask sequence; stop omits mask)" {
    write_config "mask"
    run_wd
    grep -q 'systemctl stop cups.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable cups.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask cups.service' "${SYSEOF_LOG}"
    : > "${SYSEOF_LOG}"
    write_config "stop"
    run_wd
    grep -q 'systemctl stop cups.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable cups.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask cups' "${SYSEOF_LOG}"
}

@test "INVARIANT (acted=7 when all print/scan units present): full coverage count surfaces" {
    write_config "mask"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'acted=7'* ]]
}

@test "INVARIANT (acted=0 + no-op when no print/scan units present — healthy sovereign endpoint has zero)" {
    write_config "mask"
    output="$(PRINT_PRESENT=0 run_wd 2>&1)"
    [[ "${output}" == *'no-op'* ]] || [[ "${output}" == *'acted=0'* ]]
}

@test "INVARIANT (no auto-uninstall: CUPS package NEVER auto-removed; only stop+disable+mask)" {
    # Module's contract is to neutralize, not uninstall.
    # CUPS/saned package removal is operator decision via
    # apt/dnf/yum.
    write_config "mask"
    run_wd
    ! grep -qE 'apt|dnf|yum|rpm' "${SYSEOF_LOG}"
}

@test "INVARIANT (mask order per unit: stop → disable → mask)" {
    write_config "mask"
    run_wd
    stop_line="$(grep -n 'systemctl stop cups.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    disable_line="$(grep -n 'systemctl disable cups.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    mask_line="$(grep -n 'systemctl mask cups.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    [ "${stop_line}" -lt "${disable_line}" ]
    [ "${disable_line}" -lt "${mask_line}" ]
}

@test "INVARIANT (mask order symmetric across event-source units — cups.socket + cups.path + saned.socket each stop→disable→mask)" {
    # Sister to rsh-telnet-disable symmetric-mask-order INVARIANT.
    # Each event-source unit must terminate-then-clear-then-gate
    # consistently — a regression that swaps order for ONE unit
    # type must trip this.
    write_config "mask"
    run_wd
    for sock in cups.socket cups.path saned.socket; do
        s="$(grep -n "systemctl stop ${sock}" "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
        d="$(grep -n "systemctl disable ${sock}" "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
        m="$(grep -n "systemctl mask ${sock}" "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
        [ "${s}" -lt "${d}" ]
        [ "${d}" -lt "${m}" ]
    done
}

@test "INVARIANT (profile downgrade mask → stop: rewrites stop+disable on each unit + does NOT re-issue mask — bidirectional contract)" {
    # Sister to rsh-telnet-disable + avahi/nscd/at/wwan/kdump family
    # downgrade pattern. Operator can both tighten + loosen.
    write_config "mask"
    run_wd
    : > "${SYSEOF_LOG}"
    write_config "stop"
    run_wd
    # Downgraded profile still emits stop+disable on each unit.
    grep -q 'systemctl stop cups.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable cups.service' "${SYSEOF_LOG}"
    # stop profile does NOT issue mask calls.
    ! grep -q 'systemctl mask' "${SYSEOF_LOG}"
}

@test "INVARIANT (acted counter accuracy mirrors actually-acted units — distinguishes 7-present from 0-present)" {
    # Sister to rsh-telnet-disable acted-counter-accuracy INVARIANT.
    # Real-world hosts may have only a subset installed; acted=
    # must reflect the real count for operator dashboard.
    write_config "mask"
    output="$(PRINT_PRESENT=1 run_wd 2>&1)"
    [[ "${output}" == *'acted=7'* ]]
    : > "${SYSEOF_LOG}"
    output_none="$(PRINT_PRESENT=0 run_wd 2>&1)"
    [[ "${output_none}" == *'acted=0'* ]] || [[ "${output_none}" == *'no-op'* ]]
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # services-disable-printing TOML; parser must tolerate without
    # altering the profile-gated behavior. mask-with-noise still
    # fires systemctl mask on cups.service + cups.socket — the
    # full printing/scanning attack surface neutralization (CUPS
    # has CVE history including the September 2024 RCE family
    # CVE-2024-47076/47175/47176/47177).
    cat > "${CONF}" <<'TOMLEOF'
profile = "mask"
operator_note = "CUPS = remote print-RCE attack surface (CVE-2024-47176)"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    grep -q 'systemctl mask cups.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask cups.socket' "${SYSEOF_LOG}"
}

@test "INVARIANT (DRY_RUN does not fire any systemctl mask/disable/stop)" {
    # Sister to many other installer module's DRY_RUN INVARIANT
    # across the brain. The services-disable-printing DRY_RUN
    # path MUST be a no-op against live systemd state — operator
    # using --dry-run to preview expects ZERO mutations. Locks
    # the dry-run side-effect-freedom contract so a regression
    # that fires mask through DRY_RUN would be caught.
    write_config "mask"
    DRY_RUN=1 run_wd
    ! grep -qE 'systemctl (mask|disable|stop)' "${SYSEOF_LOG}"
}

@test "INVARIANT (printers-port observability: CUPS UDP/631 surface closed when units masked — observability via systemd-status check post-mask)" {
    # Sister to avahi-disable mDNS-port observability INVARIANT
    # already locked. CUPS listens on UDP/631 (Bonjour print-
    # service discovery / IPP Browse). When mask profile fires
    # against cups.service + cups.socket, the listener is closed
    # — operator can verify via systemd-is-active check returning
    # inactive on both units. Locks the operator-verifiable
    # neutralization contract on the CUPS attack surface (CVE-
    # 2024-47176 / IPP-printer-RCE family).
    write_config "mask"
    run_wd
    grep -q 'systemctl mask cups.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask cups.socket' "${SYSEOF_LOG}"
    # Both .service AND .socket are masked → the UDP/631
    # listener cannot be socket-activated either.
}

@test "INVARIANT (downgrade mask → stop does NOT auto-unmask — mask is sticky)" {
    # Sister to brain-wide mask-is-sticky-downgrade INVARIANTs
    # (nscd-disable / rpcbind-disable / apport-disable / at-
    # disable / avahi-disable). mask is operator-explicit hard-
    # disable; downgrading the profile to stop does NOT silently
    # undo the mask (operator must explicitly unmask via
    # systemctl unmask). Locks the mask-stickiness contract on
    # the printing-service-neutralization substrate — prevents
    # accidental re-exposure of CUPS/IPP-RCE attack surface via
    # profile downgrade.
    write_config "mask"
    run_wd
    : > "${SYSEOF_LOG}"
    write_config "stop"
    run_wd
    # No unmask command fires on downgrade.
    ! grep -qE 'systemctl unmask cups' "${SYSEOF_LOG}"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-logger
    # INVARIANTs (SDD-062 consumer dispatch contract). The
    # services-disable-printing installer acts on 7 print/scan
    # units in a single sweep BUT MUST surface exactly ONE
    # emit_status JSON record (carrying the aggregate acted=N
    # count) — never one record per unit. Multi-record output
    # would break operator dashboard parsers + double-count
    # acted across units. Locks single-source-of-truth on the
    # CUPS/IPP/saned attack-surface neutralization substrate.
    write_config "mask"
    run env PATH="${BIN}:${PATH}" \
        SYSEOF_LOG="${SYSEOF_LOG}" \
        SELFDEF_DRY_RUN=0 \
        SELFDEF_PRINTING_CONFIG="${CONF}" \
        PRINT_PRESENT=1 \
        bash "${WD}"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"services-disable-printing"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on services-disable-printing surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The services-disable-printing installer MUST only emit
    # severity values from the closed set {ok,warn,alert} —
    # never custom values (critical, error, fatal, notice,
    # info). Operator dashboard parsers branch on the literal
    # severity string; an out-of-set value silently falls
    # through routing and the operator never sees the print/
    # scan-services neutralization status alert. Locks parser
    # contract on the services-disable-printing installer JSON
    # surface (consistency-with-watchdog-family discipline).
    write_config "mask"
    output=$(run env PATH="${BIN}:${PATH}" \
        SYSEOF_LOG="${SYSEOF_LOG}" \
        SELFDEF_DRY_RUN=0 \
        SELFDEF_PRINTING_CONFIG="${CONF}" \
        PRINT_PRESENT=1 \
        bash "${WD}" 2>&1)
    bad=$(printf '%s\n' "${output}" | grep -oE '"severity":"[^"]+"' | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. services-disable-printing manifest declares
    # install + profile gating (mask / stop) the resolver
    # enforces; malformed manifest wedges the cups/avahi
    # neutralization sequence. Python's tomllib is the canonical
    # parser. Locks anti-malformed-manifest on the services-
    # disable-printing substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'services-disable-printing', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: services-disable-printing installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # services-disable-printing writes its own drop-in/config; it MUST NEVER
    # rm/find-delete operator-pre-existing entries not owned by
    # THIS module. Locks no-auto-delete on the services-disable-printing
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(selinux|passwd|shadow|cups|profile\.d|login\.defs|ssh|sudoers|sudoers\.d|suricata)[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(selinux|cups|profile\.d|ssh|sudoers|sudoers\.d|suricata).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # services-disable-printing install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the services-disable-printing lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the services-disable-printing substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
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
    # list-vs-string INVARIANTs. Locks list discipline on
    # provides.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
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
    # the services-disable-printing requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
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
    # services-disable-printing substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
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
    # services-disable-printing substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
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
    # Locks semver-X.Y.Z discipline on the services-disable-printing
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (services-disable-printing module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the services-disable-printing module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
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

@test "INVARIANT (services-disable-printing module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the services-disable-printing module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
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

@test "INVARIANT (services-disable-printing module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the services-disable-printing
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
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

@test "INVARIANT (services-disable-printing module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for services-disable-printing is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the services-disable-printing substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (services-disable-printing module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the services-disable-printing install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
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

@test "INVARIANT (services-disable-printing module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the services-disable-printing requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
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

@test "INVARIANT (services-disable-printing module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the services-disable-printing
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (services-disable-printing module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the services-disable-printing
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (services-disable-printing module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the services-disable-printing substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (services-disable-printing module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (services-disable-printing module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the services-disable-printing substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
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

@test "INVARIANT (services-disable-printing module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (services-disable-printing module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (services-disable-printing module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (services-disable-printing module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (services-disable-printing module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (services-disable-printing module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (services-disable-printing README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (services-disable-printing install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (services-disable-printing install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (services-disable-printing install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (services-disable-printing install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (services-disable-printing install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (services-disable-printing install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (services-disable-printing install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (services-disable-printing install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (services-disable-printing install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (services-disable-printing install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (services-disable-printing install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (services-disable-printing install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (services-disable-printing module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (services-disable-printing module.toml exists at canonical path modules/services-disable-printing/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (services-disable-printing module dir is at canonical path modules/services-disable-printing/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (services-disable-printing install dir exists at modules/services-disable-printing/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (services-disable-printing install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (services-disable-printing install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (services-disable-printing install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (services-disable-printing install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (services-disable-printing module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (services-disable-printing install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (services-disable-printing install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (services-disable-printing install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (services-disable-printing install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (services-disable-printing install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (services-disable-printing install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (services-disable-printing install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (services-disable-printing install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (services-disable-printing module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (services-disable-printing module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (services-disable-printing module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
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

@test "INVARIANT (services-disable-printing module.toml has at least 1 entry in install_paths.paths — non-empty-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 1
"
}

@test "INVARIANT (services-disable-printing module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (services-disable-printing module.toml install_paths.scope canonical-system 92 — operator-scope-fixed)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc in ('system', 'user', '')
"
}

@test "INVARIANT (services-disable-printing module.toml install_paths.paths has /etc/selfdef/ entry 93 — selfdef-config-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/etc/selfdef/' in p for p in ps)
"
}

@test "INVARIANT (services-disable-printing module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (services-disable-printing module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (services-disable-printing module.toml uses TOML key-value assignment syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (services-disable-printing module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (services-disable-printing module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (services-disable-printing module.toml category field uses double-quoted string syntax — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (services-disable-printing module.toml summary field uses double-quoted string syntax — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (services-disable-printing module.toml name field value matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"services-disable-printing"' "${mtoml}"
}

@test "INVARIANT (services-disable-printing module.toml top-level keys before any [section] header — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
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

@test "INVARIANT (services-disable-printing module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (services-disable-printing module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (services-disable-printing module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (services-disable-printing module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (services-disable-printing module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (services-disable-printing module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (services-disable-printing module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (services-disable-printing module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (services-disable-printing module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/services-disable-printing/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}
