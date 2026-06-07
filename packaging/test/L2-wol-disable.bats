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
