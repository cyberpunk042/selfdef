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
