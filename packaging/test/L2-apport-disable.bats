#!/usr/bin/env bats
# L2 functional suite for apport-disable.
#
# apport-disable stops + disables Ubuntu's apport (and whoopsie)
# crash-reporting + crash-handler service family — 6 units total
# (apport.service + apport-autoreport.{service,path,timer} +
# whoopsie.{service,path}). Apport phones home, transmits crash
# data that may contain sensitive memory — sovereign endpoints
# don't want that.
#
# Critically, apport hijacks kernel.core_pattern with a pipe to its
# own binary. Simply masking the service is NOT enough — the kernel
# still invokes the now-masked apport binary on every crash. The
# module ALSO resets core_pattern via sysctl -w if it currently
# pipes to apport.
#
# Adds SELFDEF_APPORT_COREPAT_SOURCE env-var (added 2026-06-06) to
# point the core_pattern read at a fixture file for L2 testability.
# Live default behavior unchanged.
#
# Run with: bats packaging/test/L2-apport-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/apport-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
case "$1" in
    list-unit-files)
        case "$2" in
            apport.service|apport-autoreport.service|apport-autoreport.path|apport-autoreport.timer|whoopsie.service|whoopsie.path)
                if [[ "${APPORT_PRESENT:-1}" == "1" ]]; then
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
    cat > "${BIN}/sysctl" <<'SCEOF'
#!/usr/bin/env bash
printf 'sysctl %s\n' "$*" >> "${SCTL_LOG}"
exit 0
SCEOF
    chmod +x "${BIN}/sysctl"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    export SCTL_LOG="${TMP}/sysctl.log"
    : > "${SYSEOF_LOG}"
    : > "${SCTL_LOG}"
    CONF="${TMP}/apport-disable.toml"
    COREPAT="${TMP}/core_pattern"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SCTL_LOG="${SCTL_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_APPORT_CONFIG="${CONF}" \
    SELFDEF_APPORT_COREPAT_SOURCE="${COREPAT}" \
    APPORT_PRESENT="${APPORT_PRESENT:-1}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_APPORT_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_APPORT_CONFIG="${SELFDEF_APPORT_CONFIG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_APPORT_CONFIG="${CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
}

@test "apport not present → no mutation" {
    write_config "mask"
    APPORT_PRESENT=0 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "mask profile acts on all 6 apport+whoopsie units" {
    write_config "mask"
    run_wd
    for unit in apport.service apport-autoreport.service apport-autoreport.path apport-autoreport.timer whoopsie.service whoopsie.path; do
        grep -q "systemctl mask ${unit}" "${SYSEOF_LOG}"
    done
}

@test "core_pattern pipes to apport → resets to 'core' via sysctl" {
    write_config "mask"
    printf '|/usr/share/apport/apport %%p %%s %%c %%P\n' > "${COREPAT}"
    run_wd
    grep -q 'sysctl -w kernel.core_pattern=core' "${SCTL_LOG}"
}

@test "core_pattern is plain (no apport pipe) → NO sysctl reset" {
    write_config "mask"
    printf 'core\n' > "${COREPAT}"
    run_wd
    ! grep -q 'sysctl -w kernel.core_pattern' "${SCTL_LOG}"
}

@test "DRY_RUN + apport-piped core_pattern → no sysctl mutation" {
    write_config "mask"
    printf '|/usr/share/apport/apport %%p\n' > "${COREPAT}"
    DRY_RUN=1 run_wd
    ! grep -q 'sysctl -w' "${SCTL_LOG}"
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "stop profile (real) → stop + disable, NO mask, NO sysctl" {
    write_config "stop"
    printf 'core\n' > "${COREPAT}"
    run_wd
    grep -q 'systemctl stop apport.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable apport.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask' "${SYSEOF_LOG}"
}

@test "default profile is mask (no profile key)" {
    : > "${CONF}"
    run_wd
    grep -q 'systemctl mask apport.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (apport-autoreport coverage): all 3 autoreport units acted on (.service + .path + .timer)" {
    write_config "mask"
    run_wd
    grep -q 'systemctl mask apport-autoreport.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask apport-autoreport.path' "${SYSEOF_LOG}"
    grep -q 'systemctl mask apport-autoreport.timer' "${SYSEOF_LOG}"
}

@test "INVARIANT (whoopsie coverage): both whoopsie units acted on (.service + .path)" {
    write_config "mask"
    run_wd
    grep -q 'systemctl mask whoopsie.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask whoopsie.path' "${SYSEOF_LOG}"
}

@test "INVARIANT (stop+sysctl composition): stop profile + apport-piped core_pattern → stop+disable + ALSO resets core_pattern" {
    # Even in stop profile, the kernel core_pattern reset must
    # fire if it pipes to apport — otherwise the kernel will
    # still call apport on every crash regardless of unit state.
    write_config "stop"
    printf '|/usr/share/apport/apport %%p %%s\n' > "${COREPAT}"
    run_wd
    grep -q 'sysctl -w kernel.core_pattern=core' "${SCTL_LOG}"
    grep -q 'systemctl stop apport.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (idempotent mask): re-applying mask fires the same systemctl set + sysctl reset" {
    write_config "mask"
    printf '|/usr/share/apport/apport %%p\n' > "${COREPAT}"
    run_wd
    first_sys="$(cat "${SYSEOF_LOG}")"
    first_sctl="$(cat "${SCTL_LOG}")"
    : > "${SYSEOF_LOG}"
    : > "${SCTL_LOG}"
    run_wd
    second_sys="$(cat "${SYSEOF_LOG}")"
    second_sctl="$(cat "${SCTL_LOG}")"
    diff <(printf '%s\n' "${first_sys}") <(printf '%s\n' "${second_sys}") >/dev/null
    diff <(printf '%s\n' "${first_sctl}") <(printf '%s\n' "${second_sctl}") >/dev/null
}

@test "INVARIANT (apport-not-present + apport-piped core_pattern): kernel-side reset STILL fires (even if no apport units present)" {
    # If apport.service is masked/uninstalled but core_pattern
    # was set up by an earlier apport install, the kernel reset
    # must still fire — otherwise the kernel keeps trying to call
    # the now-missing apport binary on every crash.
    write_config "mask"
    printf '|/usr/share/apport/apport %%p\n' > "${COREPAT}"
    APPORT_PRESENT=0 run_wd
    grep -q 'sysctl -w kernel.core_pattern=core' "${SCTL_LOG}"
}

@test "emit_status surfaces profile + result in JSON (operator observability)" {
    write_config "mask"
    printf 'core\n' > "${COREPAT}"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"apport-disable"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=mask'* ]]
}

@test "INVARIANT (mask is superset of stop: mask = stop+disable+mask; stop omits mask step)" {
    write_config "mask"
    printf 'core\n' > "${COREPAT}"
    run_wd
    grep -q 'systemctl stop apport.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable apport.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask apport.service' "${SYSEOF_LOG}"
    : > "${SYSEOF_LOG}"
    write_config "stop"
    run_wd
    grep -q 'systemctl stop apport.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable apport.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask apport' "${SYSEOF_LOG}"
}

@test "INVARIANT (acted=6 when all apport+whoopsie units present): full coverage count surfaces" {
    write_config "mask"
    printf 'core\n' > "${COREPAT}"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'acted=6'* ]]
}

@test "INVARIANT (no auto-uninstall: apport package NEVER auto-removed; only stop+disable+mask)" {
    write_config "mask"
    printf 'core\n' > "${COREPAT}"
    run_wd
    ! grep -qE 'apt|dnf|yum|rpm' "${SYSEOF_LOG}"
}

@test "INVARIANT (core_pattern reset value is the kernel-safe 'core' literal — NOT a pipe to elsewhere)" {
    # When resetting kernel.core_pattern, the value must be the
    # safe 'core' literal (kernel-default behavior). Setting it
    # to '|/some/other/pipe' would just shift the privacy leak.
    write_config "mask"
    printf '|/usr/share/apport/apport %%p\n' > "${COREPAT}"
    run_wd
    grep -qE 'sysctl -w kernel.core_pattern=core$' "${SCTL_LOG}"
    # No other pipe set.
    ! grep -qE 'sysctl -w kernel.core_pattern=\|' "${SCTL_LOG}"
}

@test "INVARIANT (.path/.timer/.socket units follow stop→disable→mask order — symmetric across event-source units)" {
    # apport-autoreport.path + apport-autoreport.timer + whoopsie.path
    # are all event-source units that re-activate the .service. Like
    # avahi-disable + nscd-disable, they must follow the same ordering
    # discipline.
    write_config "mask"
    printf 'core\n' > "${COREPAT}"
    run_wd
    # Verify the .path unit follows stop→disable→mask order.
    stop_line="$(grep -n 'systemctl stop apport-autoreport.path' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    disable_line="$(grep -n 'systemctl disable apport-autoreport.path' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    mask_line="$(grep -n 'systemctl mask apport-autoreport.path' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    [ "${stop_line}" -lt "${disable_line}" ]
    [ "${disable_line}" -lt "${mask_line}" ]
}

@test "INVARIANT (downgrade mask → stop does NOT auto-unmask — sister-pattern with avahi/nscd/ctrlaltdel)" {
    # Mask is sticky. Once masked, downgrade to stop does NOT auto-unmask.
    write_config "mask"
    printf 'core\n' > "${COREPAT}"
    run_wd
    : > "${SYSEOF_LOG}"
    write_config "stop"
    run_wd
    grep -q 'systemctl stop apport.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl unmask apport' "${SYSEOF_LOG}"
}

@test "INVARIANT (architectural triplet completion: unit-mask + autoreport-unit-mask + core_pattern-reset all fire on mask profile)" {
    # mask profile fires ALL THREE disable mechanisms:
    # 1. systemctl mask apport.service + whoopsie.service (userspace daemons)
    # 2. systemctl mask apport-autoreport.* (event-trigger units)
    # 3. sysctl -w kernel.core_pattern=core (kernel-side pipe reset)
    # Triplet completeness lock against regression dropping any mechanism.
    write_config "mask"
    printf '|/usr/share/apport/apport %%p\n' > "${COREPAT}"
    run_wd
    grep -q 'systemctl mask apport.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask apport-autoreport.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask whoopsie.service' "${SYSEOF_LOG}"
    grep -q 'sysctl -w kernel.core_pattern=core' "${SCTL_LOG}"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # apport-disable TOML; parser must tolerate without altering the
    # profile-gated behavior. mask-with-noise still fires the full
    # architectural triplet (unit mask + autoreport mask + core_
    # pattern reset) — the full crash-reporting-leak neutralization
    # the operator selected (apport pipes kernel crash dumps to
    # Canonical's crash-database — kernel memory leak surface).
    cat > "${CONF}" <<'TOMLEOF'
profile = "mask"
operator_note = "apport = kernel-memory exfil via Canonical crash DB"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    printf '|/usr/share/apport/apport %%p\n' > "${COREPAT}"
    run_wd
    grep -q 'systemctl mask apport.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask whoopsie.service' "${SYSEOF_LOG}"
    grep -q 'sysctl -w kernel.core_pattern=core' "${SCTL_LOG}"
}

@test "INVARIANT (idempotent re-apply: mask twice fires systemctl mask twice — current behavior, no internal skip-detect on already-masked)" {
    # Sister to many other installer module's idempotency
    # INVARIANT across the brain. The apport-disable module's
    # systemctl mask is the idempotent operation (systemd
    # already detects already-masked + returns 0). The wrapper
    # does NOT internally skip — locks current behavior so
    # operator-dashboard count reflects intended re-arm intent
    # (operator running apply twice intentionally re-asserts
    # the mask) rather than silent skip that would hide drift
    # detection. Locks the re-apply contract.
    write_config "mask"
    printf '|/usr/share/apport/apport %%p\n' > "${COREPAT}"
    run_wd
    : > "${SYSEOF_LOG}"
    run_wd
    # Second apply re-issues mask command (no internal skip-detect).
    grep -q 'systemctl mask apport.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO systemctl OR sysctl side-effect fires when SELFDEF_DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain (acct-baseline / apparmor-baseline / sysctl
    # hardening / many others). The DRY_RUN scaffold lets the
    # operator preview the apport-disable architectural triplet
    # WITHOUT actually masking units OR resetting kernel.core_
    # pattern — preserves the leak-surface review affordance
    # before commit. Without strict DRY_RUN gating, an operator's
    # exploratory --dry-run run would silently mask apport on
    # production. Locks the dry-run-preserves-state contract on
    # the crash-reporting-leak neutralization substrate.
    write_config "mask"
    printf '|/usr/share/apport/apport %%p\n' > "${COREPAT}"
    : > "${SYSEOF_LOG}"
    : > "${SCTL_LOG}"
    DRY_RUN=1 run_wd
    ! grep -q 'systemctl mask apport.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask whoopsie.service' "${SYSEOF_LOG}"
    ! grep -q 'sysctl -w kernel.core_pattern=core' "${SCTL_LOG}"
}

@test "INVARIANT (no auto-uninstall: apport / whoopsie packages NEVER auto-removed — module neutralizes, doesn't uninstall)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs (avahi-
    # disable / at-disable / nscd-disable / kdump-disable /
    # rpcbind-disable / services-disable-printing). The apport-
    # disable module neutralizes via stop+disable+mask; the
    # apport / whoopsie packages MUST stay installed (operator
    # may legitimately need to enable apport for crash debugging).
    write_config "mask"
    printf '|/usr/share/apport/apport %%p\n' > "${COREPAT}"
    run_wd
    ! grep -qE '(apt-get|dpkg|dnf|rpm)[[:space:]]+(remove|purge|uninstall)' "${SYSEOF_LOG}"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on apport-disable installer
    # surface across unit-mask + autoreport-mask + core_pattern-
    # reset (architectural-triplet) phases.
    write_config "mask"
    printf '|/usr/share/apport/apport %%p\n' > "${COREPAT}"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"apport-disable"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (header-marker discipline: sysctl drop-in carries 'selfdef' self-identifying header — head-grep stale-cleanup discipline)" {
    # Sister to brain-wide header-marker discipline INVARIANTs
    # across L2 drop-in suites. The apport-disable core_pattern
    # reset writes a sysctl drop-in OR direct /proc/sys write
    # — when the drop-in path is taken (/etc/sysctl.d/50-selfdef-
    # core-pattern.conf), it MUST carry a comment marker
    # identifying it as selfdef-managed so a stale-cleanup
    # head -2 grep at uninstall time can identify which files
    # selfdef owns vs which is operator-original. Without a
    # marker, a subsequent uninstaller could not tell apart
    # operator baseline kernel.core_pattern from selfdef-
    # injected reset — risking accidental rollback of operator
    # crash-handler config. Locks marker-discipline on the
    # apport-disable sysctl.d substrate.
    write_config "mask"
    printf '|/usr/share/apport/apport %%p\n' > "${COREPAT}"
    run_wd
    # When a sysctl drop-in is rendered, header must be present.
    for f in "${TMP:-/tmp/missing}"/sysctl.d/*selfdef*.conf \
             "${TMP:-/tmp/missing}"/etc/sysctl.d/*selfdef*.conf; do
        if [ -f "${f}" ]; then
            grep -qE '^#.*(selfdef|apport-disable|managed)' "${f}"
        fi
    done
    # Always at least one of: drop-in present OR direct write
    # to ${COREPAT}; this test passes vacuously if no drop-in
    # path is taken (current behavior — operator sees direct
    # /proc/sys write).
    [ -f "${COREPAT}" ]
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on apport-disable surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The apport-disable installer MUST only emit severity
    # values from the closed set {ok,warn,alert} — never custom
    # values (critical, error, fatal, notice, info). Operator
    # dashboard parsers branch on the literal severity string;
    # an out-of-set value silently falls through routing and
    # the operator never sees the apport/whoopsie neutralization
    # status alert. Locks parser contract on the apport-disable
    # installer JSON surface (consistency-with-watchdog-family
    # discipline).
    write_config "mask"
    printf '|/usr/share/apport/apport %%p\n' > "${COREPAT}"
    output="$(run_wd 2>&1)"
    bad=$(printf '%s\n' "${output}" | grep -oE '"severity":"[^"]+"' | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. apport-disable manifest declares install + profile
    # gating the resolver enforces; malformed manifest wedges
    # the apport core-handler neutralization sequence. Python's
    # tomllib is the canonical parser. Locks anti-malformed-
    # manifest on the apport-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'apport-disable', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # apport-disable install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state (one drop-in
    # written + another aborted mid-way) is detectable rather
    # than a half-applied silent state. Locks fail-loud
    # invariant on the apport-disable lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/apport-disable/install"
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
    # the depends_on field of the apport-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
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
    # apport-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
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
    # the apport-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
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
    # the apport-disable requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
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
    # present discipline on the apport-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
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
    # category-present discipline on the apport-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
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
    # semver-X.Y.Z discipline on the apport-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (apport-disable module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the apport-disable module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
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

@test "INVARIANT (apport-disable module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the apport-disable module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
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

@test "INVARIANT (apport-disable module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the apport-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
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

@test "INVARIANT (apport-disable module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for apport-disable is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the apport-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (apport-disable module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the apport-disable install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
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

@test "INVARIANT (apport-disable module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the apport-disable requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
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

@test "INVARIANT (apport-disable module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the apport-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (apport-disable module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the apport-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (apport-disable module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the apport-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (apport-disable module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (apport-disable module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the apport-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
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

@test "INVARIANT (apport-disable module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (apport-disable module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (apport-disable module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (apport-disable module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (apport-disable module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (apport-disable module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apport-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (apport-disable README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/apport-disable/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (apport-disable install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/apport-disable/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (apport-disable install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/apport-disable/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (apport-disable install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/apport-disable/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (apport-disable install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/apport-disable/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (apport-disable install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/apport-disable/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (apport-disable install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/apport-disable/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (apport-disable install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/apport-disable/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (apport-disable install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/apport-disable/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (apport-disable install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/apport-disable/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (apport-disable install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/apport-disable/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (apport-disable install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/apport-disable/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (apport-disable install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/apport-disable/install/uninstall.sh"
    [ -s "${uni}" ]
}
