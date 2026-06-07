#!/usr/bin/env bats
# L2 functional suite for wol-disable.
#
# wol-disable disables Wake-on-LAN (WoL). WoL lets a magic packet
# from the network wake the host from S3/S5 sleep — the network
# packet is unauthenticated (a special MAC pattern, no keys). On
# a sovereign endpoint that's a remote-power-on surface for an
# attacker on the same broadcast domain. Disabling WoL closes
# the surface.
#
# Profiles:
#   enforce → disable WoL on every detected NIC + persist across
#             reboot/resume via systemd service triggered on
#             multi-user.target + sleep.target
#   audit   → log WoL state per NIC but don't change it (baseline
#             visibility; useful for inventory)
#
# Same systemd-service + profile-via-drop-in pattern as entropy-
# baseline. Test pattern is identical.
#
# Uses SELFDEF_LIBEXEC_DIR + SELFDEF_SYSTEMD_DIR env-vars (already
# present).
#
# Run with: bats packaging/test/L2-wol-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/wol-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/wol-disable.toml"
    LIBEXEC_DIR="${TMP}/libexec"
    SYSTEMD_DIR="${TMP}/systemd"
    mkdir -p "${LIBEXEC_DIR}" "${SYSTEMD_DIR}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_WOL_CONFIG="${CONF}" \
    SELFDEF_LIBEXEC_DIR="${LIBEXEC_DIR}" \
    SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_WOL_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_WOL_CONFIG="${SELFDEF_WOL_CONFIG}" \
        SELFDEF_LIBEXEC_DIR="${LIBEXEC_DIR}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_WOL_CONFIG="${CONF}" \
        SELFDEF_LIBEXEC_DIR="${LIBEXEC_DIR}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be enforce|audit"* ]]
}

@test "enforce profile installs libexec + service + profile drop-in" {
    write_config "enforce"
    run_wd
    [ -f "${LIBEXEC_DIR}/wol-disable.sh" ]
    [ -x "${LIBEXEC_DIR}/wol-disable.sh" ]
    [ -f "${SYSTEMD_DIR}/selfdef-wol-disable.service" ]
    [ -f "${SYSTEMD_DIR}/selfdef-wol-disable.service.d/50-profile.conf" ]
    grep -q 'SELFDEF_WOL_PROFILE=enforce' "${SYSTEMD_DIR}/selfdef-wol-disable.service.d/50-profile.conf"
}

@test "audit profile drop-in carries SELFDEF_WOL_PROFILE=audit" {
    write_config "audit"
    run_wd
    grep -q 'SELFDEF_WOL_PROFILE=audit' "${SYSTEMD_DIR}/selfdef-wol-disable.service.d/50-profile.conf"
}

@test "service enable + start + daemon-reload fire on initial install" {
    write_config "enforce"
    run_wd
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
    grep -q 'systemctl enable selfdef-wol-disable.service' "${SYSEOF_LOG}"
    grep -q 'systemctl start selfdef-wol-disable.service' "${SYSEOF_LOG}"
}

@test "libexec script chmod 0755" {
    write_config "enforce"
    run_wd
    [ "$(stat -c '%a' "${LIBEXEC_DIR}/wol-disable.sh")" = "755" ]
}

@test "service + drop-in chmod 0644" {
    write_config "enforce"
    run_wd
    [ "$(stat -c '%a' "${SYSTEMD_DIR}/selfdef-wol-disable.service")" = "644" ]
    [ "$(stat -c '%a' "${SYSTEMD_DIR}/selfdef-wol-disable.service.d/50-profile.conf")" = "644" ]
}

@test "INVARIANT: idempotent — re-install with identical content fires NO daemon-reload" {
    write_config "enforce"
    run_wd
    : > "${SYSEOF_LOG}"
    run_wd
    ! grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT: profile change enforce → audit updates drop-in + fires daemon-reload" {
    write_config "enforce"
    run_wd
    write_config "audit"
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'SELFDEF_WOL_PROFILE=audit' "${SYSTEMD_DIR}/selfdef-wol-disable.service.d/50-profile.conf"
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT: DRY_RUN does not install anything or fire systemctl" {
    write_config "enforce"
    DRY_RUN=1 run_wd
    ! [ -f "${LIBEXEC_DIR}/wol-disable.sh" ]
    ! grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "default profile is enforce (no profile key — the secure default)" {
    : > "${CONF}"
    run_wd
    grep -q 'SELFDEF_WOL_PROFILE=enforce' "${SYSTEMD_DIR}/selfdef-wol-disable.service.d/50-profile.conf"
}

@test "INVARIANT (profile downgrade audit → enforce): rewrites drop-in back + fires reload" {
    write_config "audit"
    run_wd
    grep -q 'SELFDEF_WOL_PROFILE=audit' "${SYSTEMD_DIR}/selfdef-wol-disable.service.d/50-profile.conf"
    write_config "enforce"
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'SELFDEF_WOL_PROFILE=enforce' "${SYSTEMD_DIR}/selfdef-wol-disable.service.d/50-profile.conf"
    ! grep -q 'SELFDEF_WOL_PROFILE=audit' "${SYSTEMD_DIR}/selfdef-wol-disable.service.d/50-profile.conf"
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT (idempotent mtime): byte-identical re-install preserves all 3 file mtimes" {
    write_config "enforce"
    run_wd
    mtime_libexec_before="$(stat -c '%Y' "${LIBEXEC_DIR}/wol-disable.sh")"
    mtime_service_before="$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-wol-disable.service")"
    mtime_dropin_before="$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-wol-disable.service.d/50-profile.conf")"
    sleep 1
    run_wd
    [ "${mtime_libexec_before}" = "$(stat -c '%Y' "${LIBEXEC_DIR}/wol-disable.sh")" ]
    [ "${mtime_service_before}" = "$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-wol-disable.service")" ]
    [ "${mtime_dropin_before}" = "$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-wol-disable.service.d/50-profile.conf")" ]
}

@test "INVARIANT (libexec actually probes ethtool for NIC list + WoL state)" {
    write_config "enforce"
    run_wd
    grep -qE 'ethtool' "${LIBEXEC_DIR}/wol-disable.sh"
}

@test "INVARIANT (service unit references libexec script)" {
    write_config "enforce"
    run_wd
    grep -qE '^ExecStart=' "${SYSTEMD_DIR}/selfdef-wol-disable.service"
    grep -q 'wol-disable' "${SYSTEMD_DIR}/selfdef-wol-disable.service"
}

@test "INVARIANT (service unit ties to sleep.target — survives suspend/resume)" {
    # WoL state is reset on resume from S3 — the unit must fire on
    # resume, not just at boot. WantedBy=multi-user.target + sleep.target
    # is the canonical pattern.
    write_config "enforce"
    run_wd
    grep -qE 'WantedBy=.*(multi-user|sleep)\.target' "${SYSTEMD_DIR}/selfdef-wol-disable.service"
}

@test "INVARIANT (no render-timestamp in any installed file): defeats cmp -s idempotency" {
    write_config "enforce"
    run_wd
    for f in "${LIBEXEC_DIR}/wol-disable.sh" \
             "${SYSTEMD_DIR}/selfdef-wol-disable.service" \
             "${SYSTEMD_DIR}/selfdef-wol-disable.service.d/50-profile.conf"; do
        ! grep -qE '^# Generated [0-9]{4}-' "$f"
    done
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates all 3 files + fires daemon-reload)" {
    write_config "enforce"
    run_wd
    [ -f "${SYSTEMD_DIR}/selfdef-wol-disable.service" ]
    rm -f "${LIBEXEC_DIR}/wol-disable.sh" \
          "${SYSTEMD_DIR}/selfdef-wol-disable.service" \
          "${SYSTEMD_DIR}/selfdef-wol-disable.service.d/50-profile.conf"
    : > "${SYSEOF_LOG}"
    run_wd
    [ -f "${LIBEXEC_DIR}/wol-disable.sh" ]
    [ -f "${SYSTEMD_DIR}/selfdef-wol-disable.service" ]
    [ -f "${SYSTEMD_DIR}/selfdef-wol-disable.service.d/50-profile.conf" ]
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "enforce"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"wol-disable"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=enforce'* ]]
}

@test "INVARIANT (libexec carries ethtool -s <iface> wol d — the actual WoL-disable mechanism)" {
    # Beyond just probing for WoL state, the libexec MUST also
    # CHANGE state (ethtool -s <iface> wol d). Lock the change-state
    # directive on top of the probe-state ethtool call.
    write_config "enforce"
    run_wd
    libexec="${LIBEXEC_DIR}/wol-disable.sh"
    grep -qE 'ethtool -s|ethtool --change' "${libexec}"
    grep -qE 'wol\s+d|wol\s*=\s*d' "${libexec}"
}

@test "INVARIANT (service unit header marker — operator-audit-trail via Description/Documentation)" {
    write_config "enforce"
    run_wd
    grep -qE '^Description=.*selfdef|^Documentation=.*selfdef|^#.*selfdef|^#.*managed-by' "${SYSTEMD_DIR}/selfdef-wol-disable.service"
}

@test "INVARIANT (libexec is shell-sourceable: bash -n parses cleanly — service ExecStart contract)" {
    # The libexec script runs at boot + sleep. bash -n must parse
    # cleanly (no malformed syntax, no unterminated quotes). Sister
    # to umask-baseline + shell-timeout-baseline + tensor-parallel-
    # inference shell-sourceable INVARIANT.
    write_config "enforce"
    run_wd
    bash -n "${LIBEXEC_DIR}/wol-disable.sh"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # wol-disable TOML; parser must tolerate without altering the
    # profile-gated behavior. enforce-with-noise still installs
    # the service + timer + libexec triplet AND the libexec
    # carries ethtool -s <iface> wol d (the actual WoL-disable
    # mechanism — closes the magic-packet remote-wakeup attack
    # surface).
    cat > "${CONF}" <<'TOMLEOF'
profile = "enforce"
operator_note = "WoL = magic-packet remote wakeup = surveillance-evading wakeup"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    [ -f "${LIBEXEC_DIR}/wol-disable.sh" ]
    grep -qE 'ethtool -s .* wol d' "${LIBEXEC_DIR}/wol-disable.sh"
}

@test "INVARIANT (service is Type=oneshot — runs to completion then exits, no daemon-residency)" {
    # Sister to many other installer module's systemd unit
    # contract INVARIANTs. The selfdef-wol-disable.service runs
    # ethtool to clear WoL once per fire then exits — it does
    # NOT need to run as a long-lived daemon. Type=oneshot is
    # the correct systemd primitive (vs simple/forking/notify
    # which all assume a long-running process). A regression
    # that switched to Type=simple would silently make the
    # unit fail-cycle on every fire (systemd would expect a
    # daemon to stay running but the script exits immediately).
    write_config "enforce"
    run_wd
    grep -qE '^Type=oneshot' "${SYSTEMD_DIR}/selfdef-wol-disable.service"
}

@test "INVARIANT (service unit fires on network-online.target — wait until interface is up before WoL clear)" {
    # Sister to oneshot-Type INVARIANT. WoL is a NIC property
    # — ethtool -s wol d needs the interface UP to take effect.
    # The service unit MUST declare After=/Wants= on network-
    # online.target (or sysinit.target) so it doesn't fire
    # before the kernel finishes interface bring-up.
    write_config "enforce"
    run_wd
    grep -qE '^(After|Wants|Requires)=.*(network-online|sysinit|network).target' "${SYSTEMD_DIR}/selfdef-wol-disable.service" \
        || grep -qE '^WantedBy=multi-user.target' "${SYSTEMD_DIR}/selfdef-wol-disable.service"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on wol-disable installer surface
    # across libexec + service-unit + drop-in phases.
    write_config "enforce"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"wol-disable"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (libexec chmod 0755 — executable contract for ExecStart=)" {
    # Sister to brain-wide libexec chmod 0755 INVARIANTs across
    # L2 systemd-libexec suites. The wol-disable libexec script
    # at /usr/libexec/selfdef/wol-disable.sh is invoked by the
    # systemd service unit ExecStart= and MUST be executable
    # mode 0755 (world-readable + group-readable + root-exec).
    # Mode 0644 would defeat the ExecStart= contract (systemd
    # refuses to invoke a non-executable script). Mode 0755 is
    # the canonical libexec convention — world-readable for
    # operator inspection + execute permission for systemd
    # invocation. Locks file-mode contract on the wol-disable
    # libexec substrate.
    write_config "enforce"
    run_wd
    libexec_path=""
    for candidate in "${LIBEXEC_DIR:-/tmp/missing}"/wol-disable.sh \
                     "${LIBEXEC_DIR:-/tmp/missing}"/selfdef-wol-disable \
                     "${LIBEXEC_DIR:-/tmp/missing}"/*; do
        [ -f "${candidate}" ] && libexec_path="${candidate}" && break
    done
    [ -n "${libexec_path}" ]
    mode="$(stat -c '%a' "${libexec_path}")"
    [ "${mode}" = "755" ] || [ "${mode}" = "750" ] || [ "${mode}" = "700" ]
}

@test "INVARIANT (no auto-uninstall: wol-disable NEVER emits package-remove commands on ethtool)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The wol-disable installer wires libexec + svc
    # + timer to invoke ethtool -s <iface> wol d but MUST NEVER
    # emit shell commands that uninstall the ethtool package
    # itself (apt/dpkg/dnf/rpm/yum remove|purge|uninstall
    # ethtool). Silent auto-removal would leave the host
    # unable to actually disable WoL on subsequent boots —
    # defeating the whole purpose of the module. Locks anti-
    # package-removal contract on the wol-disable substrate.
    write_config "enforce"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+ethtool'
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. wol-disable manifest declares install + profile
    # gating the resolver enforces; malformed manifest wedges
    # the WoL ethtool-disable libexec baseline. Python's tomllib
    # is the canonical parser. Locks anti-malformed-manifest on
    # the wol-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'wol-disable', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: wol-disable installer NEVER deletes operator-pre-existing modprobe.d/sysctl.d entries — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # wol-disable writes its own modprobe blacklist drop-in;
    # it MUST NEVER rm/find-delete operator-pre-existing
    # /etc/modprobe.d entries not owned by THIS module. Locks
    # no-auto-delete on the wol-disable installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/wol-disable/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/modprobe\.d[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/modprobe\.d.*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # wol-disable install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the wol-disable lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/wol-disable/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the wol-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
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
    # the wol-disable requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
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
    # wol-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
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
    # wol-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
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
    # Locks semver-X.Y.Z discipline on the wol-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (wol-disable module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the wol-disable module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
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

@test "INVARIANT (wol-disable module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the wol-disable module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
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

@test "INVARIANT (wol-disable module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the wol-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
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

@test "INVARIANT (wol-disable module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for wol-disable is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the wol-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (wol-disable module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the wol-disable install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
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

@test "INVARIANT (wol-disable module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the wol-disable requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
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

@test "INVARIANT (wol-disable module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the wol-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (wol-disable module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the wol-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (wol-disable module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the wol-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (wol-disable module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (wol-disable module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the wol-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
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

@test "INVARIANT (wol-disable module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (wol-disable module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (wol-disable module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (wol-disable module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (wol-disable module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (wol-disable module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wol-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (wol-disable README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/wol-disable/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (wol-disable install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/wol-disable/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (wol-disable install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/wol-disable/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (wol-disable install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/wol-disable/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (wol-disable install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/wol-disable/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (wol-disable install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/wol-disable/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (wol-disable install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/wol-disable/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (wol-disable install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/wol-disable/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (wol-disable install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/wol-disable/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (wol-disable install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/wol-disable/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (wol-disable install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/wol-disable/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (wol-disable install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/wol-disable/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (wol-disable install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/wol-disable/install/uninstall.sh"
    [ -s "${uni}" ]
}
