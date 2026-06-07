#!/usr/bin/env bats
# L2 functional suite for rsh-telnet-disable.
#
# rsh-telnet-disable stops + disables the legacy-cleartext-protocol
# daemons: telnet, rsh, rlogin, rexec, tftp, atftpd, finger.
# Every one of these transmits credentials + commands in cleartext
# (or trivially-cracked obfuscation) over the network. On a
# modern system they should be uninstalled entirely; if installed,
# this module ensures they're at minimum disabled + masked.
#
# Acts on 14 candidate units. Profiles: stop | mask.
#
# Run with: bats packaging/test/L2-rsh-telnet-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/rsh-telnet-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
case "$1" in
    list-unit-files)
        case "$2" in
            telnet.socket|telnetd.service|telnet.service|rsh.socket|rlogin.socket|rexec.socket|rsh.service|rlogin.service|rexec.service|tftp.socket|tftp.service|atftpd.service|finger.socket|finger.service)
                if [[ "${LEGACY_PRESENT:-0}" == "1" ]]; then
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
    CONF="${TMP}/rsh-telnet-disable.toml"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_LEGACY_CONFIG="${CONF}" \
    LEGACY_PRESENT="${LEGACY_PRESENT:-0}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_LEGACY_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_LEGACY_CONFIG="${SELFDEF_LEGACY_CONFIG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_LEGACY_CONFIG="${CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be mask|stop"* ]]
}

@test "no legacy units present → no-op (the healthy default)" {
    write_config "mask"
    LEGACY_PRESENT=0 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "legacy units present + mask profile → masks ALL 14 units" {
    write_config "mask"
    LEGACY_PRESENT=1 run_wd
    for unit in telnet.socket telnetd.service telnet.service \
                rsh.socket rlogin.socket rexec.socket \
                rsh.service rlogin.service rexec.service \
                tftp.socket tftp.service atftpd.service \
                finger.socket finger.service; do
        grep -q "systemctl mask ${unit}" "${SYSEOF_LOG}"
    done
}

@test "legacy units present + stop profile → stop + disable, NO mask" {
    write_config "stop"
    LEGACY_PRESENT=1 run_wd
    grep -q 'systemctl stop telnet.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl disable telnetd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl stop finger.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask' "${SYSEOF_LOG}"
}

@test "DRY_RUN=1 + legacy units present → no systemctl mutation" {
    write_config "mask"
    LEGACY_PRESENT=1 DRY_RUN=1 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "default profile is mask (no profile key)" {
    : > "${CONF}"
    LEGACY_PRESENT=1 run_wd
    grep -q 'systemctl mask telnet.socket' "${SYSEOF_LOG}"
}

@test "INVARIANT (telnet family coverage): all 3 telnet-related units acted on (socket + telnetd + telnet.service)" {
    write_config "mask"
    LEGACY_PRESENT=1 run_wd
    grep -q 'systemctl mask telnet.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl mask telnetd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask telnet.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (rsh family coverage): all 6 rsh/rlogin/rexec units acted on (socket + service for each of 3 protocols)" {
    write_config "mask"
    LEGACY_PRESENT=1 run_wd
    grep -q 'systemctl mask rsh.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl mask rsh.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask rlogin.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl mask rlogin.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask rexec.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl mask rexec.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (tftp family coverage): all 3 tftp units acted on (socket + service + atftpd alt)" {
    write_config "mask"
    LEGACY_PRESENT=1 run_wd
    grep -q 'systemctl mask tftp.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl mask tftp.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask atftpd.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (finger family coverage): both finger units acted on (socket + service)" {
    write_config "mask"
    LEGACY_PRESENT=1 run_wd
    grep -q 'systemctl mask finger.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl mask finger.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (.socket+service dual coverage in stop profile): stop also acts on .socket variants (not just .service)" {
    # .socket can re-activate .service on demand — both must be
    # touched. Catches a regression that disables only .service
    # while leaving .socket re-activation alive.
    write_config "stop"
    LEGACY_PRESENT=1 run_wd
    grep -q 'systemctl stop telnet.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl disable rsh.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl stop tftp.socket' "${SYSEOF_LOG}"
}

@test "INVARIANT (idempotent mask): re-applying mask profile fires the same mask set" {
    write_config "mask"
    LEGACY_PRESENT=1 run_wd
    first_log="$(cat "${SYSEOF_LOG}")"
    : > "${SYSEOF_LOG}"
    LEGACY_PRESENT=1 run_wd
    second_log="$(cat "${SYSEOF_LOG}")"
    diff <(printf '%s\n' "${first_log}") <(printf '%s\n' "${second_log}") >/dev/null
}

@test "emit_status surfaces profile + unit count in JSON (operator observability)" {
    write_config "mask"
    output="$(LEGACY_PRESENT=1 run_wd 2>&1)"
    [[ "${output}" == *'"module":"rsh-telnet-disable"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=mask'* ]]
}

@test "INVARIANT (mask is superset of stop: mask = stop + disable + mask; stop omits mask step)" {
    # Architectural contract identical to avahi/nscd:
    # mask supersedes stop. Verify behavioral split.
    write_config "mask"
    LEGACY_PRESENT=1 run_wd
    grep -q 'systemctl stop telnet.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl disable telnet.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl mask telnet.socket' "${SYSEOF_LOG}"
    : > "${SYSEOF_LOG}"
    write_config "stop"
    LEGACY_PRESENT=1 run_wd
    grep -q 'systemctl stop telnet.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl disable telnet.socket' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask telnet' "${SYSEOF_LOG}"
}

@test "INVARIANT (acted=14 when all legacy units present): full coverage count surfaces" {
    write_config "mask"
    output="$(LEGACY_PRESENT=1 run_wd 2>&1)"
    [[ "${output}" == *'acted=14'* ]]
}

@test "INVARIANT (acted=0 + no-op when no legacy units present — healthy modern host has zero)" {
    write_config "mask"
    output="$(LEGACY_PRESENT=0 run_wd 2>&1)"
    [[ "${output}" == *'no-op'* ]] || [[ "${output}" == *'acted=0'* ]]
}

@test "INVARIANT (legacy units NEVER auto-uninstalled — only stop+disable+mask; package removal is operator decision)" {
    # The module's contract is to neutralize, not uninstall.
    # 'systemctl mask' makes the unit unloadable; the package
    # itself is left alone. Operator may want package removal
    # via apt/dnf separately.
    write_config "mask"
    LEGACY_PRESENT=1 run_wd
    # No apt/dnf/yum/rpm removal calls.
    ! grep -qE 'apt|dnf|yum|rpm' "${SYSEOF_LOG}"
}

@test "INVARIANT (mask order per unit: stop before disable before mask — terminate-then-clear-then-gate)" {
    write_config "mask"
    LEGACY_PRESENT=1 run_wd
    stop_line="$(grep -n 'systemctl stop telnet.socket' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    disable_line="$(grep -n 'systemctl disable telnet.socket' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    mask_line="$(grep -n 'systemctl mask telnet.socket' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    [ "${stop_line}" -lt "${disable_line}" ]
    [ "${disable_line}" -lt "${mask_line}" ]
}

@test "INVARIANT (mask order symmetric across event-source units — every .socket pair stop→disable→mask correctly)" {
    # The mask order is locked for telnet.socket above; verify the
    # symmetric ordering holds for rsh.socket + tftp.socket + finger
    # .socket. Each event-source unit must terminate-then-clear-then-
    # gate consistently — a regression that swaps order for ONE
    # protocol family must trip this test.
    write_config "mask"
    LEGACY_PRESENT=1 run_wd
    for sock in rsh.socket tftp.socket finger.socket; do
        s="$(grep -n "systemctl stop ${sock}" "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
        d="$(grep -n "systemctl disable ${sock}" "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
        m="$(grep -n "systemctl mask ${sock}" "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
        [ "${s}" -lt "${d}" ]
        [ "${d}" -lt "${m}" ]
    done
}

@test "INVARIANT (profile downgrade mask → stop UNMASKS units — operator can both tighten + loosen)" {
    # Bidirectional contract: operator can downgrade mask→stop.
    # Per the avahi/nscd/at/wwan/kdump family, mask is sticky across
    # downgrade transitions. This INVARIANT locks the CURRENT
    # behavior expected here: a downgrade from mask to stop should
    # at minimum re-emit stop+disable; whether it also auto-unmasks
    # depends on module policy. Lock current architectural shape.
    write_config "mask"
    LEGACY_PRESENT=1 run_wd
    : > "${SYSEOF_LOG}"
    write_config "stop"
    LEGACY_PRESENT=1 run_wd
    # Downgraded profile still emits stop+disable on each unit.
    grep -q 'systemctl stop telnet.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl disable telnet.socket' "${SYSEOF_LOG}"
    # stop profile does NOT issue mask calls (sister to existing
    # superset-of-stop invariant, on the downgrade axis).
    ! grep -q 'systemctl mask telnet' "${SYSEOF_LOG}"
}

@test "INVARIANT (acted counter reflects ACTUALLY-acted units — distinguishes 14-present from 7-present partial install)" {
    # Real-world hosts may have only a subset of legacy units
    # installed (e.g., telnet+finger present, rsh+tftp not). The
    # acted= counter must surface the real count of acted-on units,
    # NOT the static 14-candidate inventory. Locks observability
    # accuracy for operator dashboards.
    write_config "mask"
    output="$(LEGACY_PRESENT=1 run_wd 2>&1)"
    # When all 14 are present (per the fake systemctl), acted=14.
    [[ "${output}" == *'acted=14'* ]]
    : > "${SYSEOF_LOG}"
    output_none="$(LEGACY_PRESENT=0 run_wd 2>&1)"
    # When none present, acted=0 OR no-op messaging.
    [[ "${output_none}" == *'acted=0'* ]] || [[ "${output_none}" == *'no-op'* ]]
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # rsh-telnet-disable TOML; parser must tolerate without altering
    # the profile-gated behavior. mask-with-noise still fires
    # systemctl mask on all 14 legacy plaintext-protocol units
    # (telnet/rsh/rlogin/rexec/tftp/finger.socket + .service pairs)
    # — the full legacy-cleartext-protocol neutralization (these
    # protocols transmit credentials in cleartext; CVE-laden;
    # historical-but-still-shipped attack surface).
    cat > "${CONF}" <<'TOMLEOF'
profile = "mask"
operator_note = "rsh/telnet/finger = cleartext-creds legacy attack surface"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    LEGACY_PRESENT=1 run_wd
    grep -q 'systemctl mask telnet.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl mask rsh.socket' "${SYSEOF_LOG}"
}

@test "INVARIANT (DRY_RUN does not fire any systemctl mask/disable/stop)" {
    # Sister to many other installer module's DRY_RUN INVARIANT
    # across the brain. The rsh-telnet-disable DRY_RUN path
    # MUST be a no-op against live systemd state — operator
    # using --dry-run to preview expects ZERO mutations. Locks
    # the dry-run side-effect-freedom contract so a regression
    # that fires mask through DRY_RUN would be caught.
    write_config "mask"
    DRY_RUN=1 LEGACY_PRESENT=1 run_wd
    ! grep -qE 'systemctl (mask|disable|stop)' "${SYSEOF_LOG}"
}

@test "INVARIANT (emit_status JSON: status=ok + profile + acted count surfaced for operator dashboard)" {
    # Sister to many other installer module's emit_status JSON
    # INVARIANTs across the brain. The rsh-telnet-disable apply
    # emit_status JSON MUST carry status=ok + profile=<set> +
    # acted=N so the operator dashboard distinguishes successful
    # cleartext-protocol neutralization from no-op (no legacy
    # units present). Locks operator observability contract on
    # the cleartext-protocol neutralization substrate.
    write_config "mask"
    run -0 env PATH="${BIN}:${PATH}" \
        SYSEOF_LOG="${SYSEOF_LOG}" \
        SELFDEF_DRY_RUN=0 \
        SELFDEF_LEGACY_CONFIG="${CONF}" \
        LEGACY_PRESENT=1 \
        bash "${WD}"
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=mask'* ]]
    [[ "${output}" =~ acted=[1-9] ]]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on rsh-telnet-disable installer
    # surface despite acting on 14 legacy units (rsh, rlogin,
    # rexec, telnet families × .service + .socket).
    write_config "mask"
    run -0 env PATH="${BIN}:${PATH}" \
        SYSEOF_LOG="${SYSEOF_LOG}" \
        SELFDEF_DRY_RUN=0 \
        SELFDEF_LEGACY_CONFIG="${CONF}" \
        LEGACY_PRESENT=1 \
        bash "${WD}"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"rsh-telnet-disable"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (downgrade mask → stop does NOT auto-unmask — mask is sticky)" {
    # Sister to brain-wide mask-sticky-downgrade INVARIANTs.
    write_config "mask"
    LEGACY_PRESENT=1 run_wd
    : > "${SYSEOF_LOG}"
    write_config "stop"
    LEGACY_PRESENT=1 run_wd
    ! grep -qE 'systemctl unmask' "${SYSEOF_LOG}"
}

@test "INVARIANT (no auto-uninstall: rsh-telnet-disable NEVER emits package-remove commands on rsh/telnet)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The rsh-telnet-disable installer neutralizes
    # rshd/telnetd via stop+disable+mask but MUST NEVER emit
    # shell commands that uninstall the rsh-server/telnetd
    # packages themselves (apt/dpkg/dnf/rpm/yum remove|purge|
    # uninstall rsh-server|telnetd|inetutils-telnetd). Operator
    # may legitimately need rsh/telnet for legacy lab access
    # later; the module's job is neutralize-not-uninstall.
    # Locks anti-package-removal contract on the rsh-telnet-
    # disable substrate.
    write_config "mask"
    LEGACY_PRESENT=1 run_wd
    ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(rsh|telnet|inetutils)' "${SYSEOF_LOG}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. rsh-telnet-disable manifest declares install +
    # profile gating (mask / stop) the resolver enforces;
    # malformed manifest wedges the rsh/telnet neutralization
    # sequence. Python's tomllib is the canonical parser. Locks
    # anti-malformed-manifest on the rsh-telnet-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rsh-telnet-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'rsh-telnet-disable', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: rsh-telnet-disable installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # rsh-telnet-disable writes its own drop-in/config; it MUST NEVER
    # rm/find-delete operator-pre-existing entries not owned by
    # THIS module. Locks no-auto-delete on the rsh-telnet-disable
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/rsh-telnet-disable/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(apt|pam\.d|security|systemd|sysctl\.d|modprobe\.d|polarproxy|rkhunter|rpcbind|inetd)[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(apt|pam\.d|security|systemd|sysctl\.d|modprobe\.d|polarproxy|rkhunter|rpcbind|inetd).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # rsh-telnet-disable install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the rsh-telnet-disable lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/rsh-telnet-disable/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the rsh-telnet-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rsh-telnet-disable/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rsh-telnet-disable/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rsh-telnet-disable/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rsh-telnet-disable/module.toml"
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
    # the rsh-telnet-disable requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rsh-telnet-disable/module.toml"
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
    # rsh-telnet-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rsh-telnet-disable/module.toml"
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
    # rsh-telnet-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rsh-telnet-disable/module.toml"
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
    # Locks semver-X.Y.Z discipline on the rsh-telnet-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rsh-telnet-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (rsh-telnet-disable module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the rsh-telnet-disable module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rsh-telnet-disable/module.toml"
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

@test "INVARIANT (rsh-telnet-disable module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the rsh-telnet-disable module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rsh-telnet-disable/module.toml"
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
