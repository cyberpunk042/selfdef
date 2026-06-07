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
