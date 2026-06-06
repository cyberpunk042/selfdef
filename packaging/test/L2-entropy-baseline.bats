#!/usr/bin/env bats
# L2 functional suite for entropy-baseline.
#
# entropy-baseline installs a systemd-timer that periodically
# checks /proc/sys/kernel/random/entropy_avail and reports under-
# threshold conditions. Low entropy in kernel RNG pool means weak
# random numbers — predictable session keys, weak ASLR, broken
# TLS, broken SSH host-key generation, predictable container
# UUIDs.
#
# Profiles:
#   report  → log + alert on low entropy
#   enforce → also exit non-zero (systemd records failure that
#             surfaces via the doctor / dashboard)
#
# Test pattern: install fixtures, verify systemd unit files +
# libexec script land at the right paths with right perms +
# verify the profile drop-in carries the configured profile.
#
# Uses SELFDEF_LIBEXEC_DIR + SELFDEF_SYSTEMD_DIR env-vars
# (already present) for L2 testability.
#
# Run with: bats packaging/test/L2-entropy-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/entropy-baseline/install/apply.sh"

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
    CONF="${TMP}/entropy-baseline.toml"
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
    SELFDEF_ENTROPY_CONFIG="${CONF}" \
    SELFDEF_LIBEXEC_DIR="${LIBEXEC_DIR}" \
    SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_ENTROPY_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_ENTROPY_CONFIG="${SELFDEF_ENTROPY_CONFIG}" \
        SELFDEF_LIBEXEC_DIR="${LIBEXEC_DIR}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_ENTROPY_CONFIG="${CONF}" \
        SELFDEF_LIBEXEC_DIR="${LIBEXEC_DIR}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be report|enforce"* ]]
}

@test "report profile installs libexec script + service + timer + profile drop-in" {
    write_config "report"
    run_wd
    [ -f "${LIBEXEC_DIR}/entropy-baseline.sh" ]
    [ -x "${LIBEXEC_DIR}/entropy-baseline.sh" ]
    [ -f "${SYSTEMD_DIR}/selfdef-entropy.service" ]
    [ -f "${SYSTEMD_DIR}/selfdef-entropy.timer" ]
    [ -f "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf" ]
    # The profile drop-in carries SELFDEF_ENTROPY_PROFILE=report.
    grep -q 'SELFDEF_ENTROPY_PROFILE=report' "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf"
}

@test "enforce profile drop-in carries SELFDEF_ENTROPY_PROFILE=enforce" {
    write_config "enforce"
    run_wd
    grep -q 'SELFDEF_ENTROPY_PROFILE=enforce' "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf"
}

@test "libexec script has chmod 0755 (executable system-script convention)" {
    write_config "report"
    run_wd
    [ "$(stat -c '%a' "${LIBEXEC_DIR}/entropy-baseline.sh")" = "755" ]
}

@test "service + timer files have chmod 0644 (system-config convention)" {
    write_config "report"
    run_wd
    [ "$(stat -c '%a' "${SYSTEMD_DIR}/selfdef-entropy.service")" = "644" ]
    [ "$(stat -c '%a' "${SYSTEMD_DIR}/selfdef-entropy.timer")" = "644" ]
    [ "$(stat -c '%a' "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf")" = "644" ]
}

@test "systemctl daemon-reload + timer enable fire when files changed" {
    write_config "report"
    run_wd
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
    grep -q 'systemctl enable --now selfdef-entropy.timer' "${SYSEOF_LOG}"
}

@test "INVARIANT: idempotent — re-install with identical content fires NO daemon-reload" {
    write_config "report"
    run_wd
    : > "${SYSEOF_LOG}"
    run_wd
    ! grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT: profile change report → enforce updates drop-in + fires daemon-reload" {
    write_config "report"
    run_wd
    write_config "enforce"
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'SELFDEF_ENTROPY_PROFILE=enforce' "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf"
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT: DRY_RUN does not install anything or fire systemctl" {
    write_config "report"
    DRY_RUN=1 run_wd
    ! [ -f "${LIBEXEC_DIR}/entropy-baseline.sh" ]
    ! [ -f "${SYSTEMD_DIR}/selfdef-entropy.service" ]
    ! grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "default profile is report (no profile key — the safe default)" {
    : > "${CONF}"
    run_wd
    grep -q 'SELFDEF_ENTROPY_PROFILE=report' "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf"
}

@test "INVARIANT (profile downgrade enforce → report): rewrites drop-in back + fires reload" {
    write_config "enforce"
    run_wd
    grep -q 'SELFDEF_ENTROPY_PROFILE=enforce' "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf"
    write_config "report"
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'SELFDEF_ENTROPY_PROFILE=report' "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf"
    ! grep -q 'SELFDEF_ENTROPY_PROFILE=enforce' "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf"
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT (idempotent mtime): byte-identical re-install preserves all 4 file mtimes" {
    write_config "report"
    run_wd
    mtime_libexec_before="$(stat -c '%Y' "${LIBEXEC_DIR}/entropy-baseline.sh")"
    mtime_service_before="$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-entropy.service")"
    mtime_timer_before="$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-entropy.timer")"
    mtime_dropin_before="$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf")"
    sleep 1
    run_wd
    [ "${mtime_libexec_before}" = "$(stat -c '%Y' "${LIBEXEC_DIR}/entropy-baseline.sh")" ]
    [ "${mtime_service_before}" = "$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-entropy.service")" ]
    [ "${mtime_timer_before}" = "$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-entropy.timer")" ]
    [ "${mtime_dropin_before}" = "$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf")" ]
}

@test "INVARIANT (libexec script reads /proc/sys/kernel/random/entropy_avail — actually probes the kernel knob)" {
    write_config "report"
    run_wd
    grep -qE '/proc/sys/kernel/random/entropy_avail' "${LIBEXEC_DIR}/entropy-baseline.sh"
}

@test "INVARIANT (service unit references libexec script — wiring is correct)" {
    write_config "report"
    run_wd
    grep -qE '^ExecStart=' "${SYSTEMD_DIR}/selfdef-entropy.service"
    grep -q 'entropy-baseline' "${SYSTEMD_DIR}/selfdef-entropy.service"
}

@test "INVARIANT (timer unit carries OnCalendar / OnBootSec — actually fires periodically)" {
    write_config "report"
    run_wd
    grep -qE '(OnCalendar|OnBootSec|OnUnitActiveSec)=' "${SYSTEMD_DIR}/selfdef-entropy.timer"
}

@test "INVARIANT (no render-timestamp in any installed file): defeats cmp -s idempotency" {
    write_config "report"
    run_wd
    for f in "${LIBEXEC_DIR}/entropy-baseline.sh" \
             "${SYSTEMD_DIR}/selfdef-entropy.service" \
             "${SYSTEMD_DIR}/selfdef-entropy.timer" \
             "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf"; do
        ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "$f"
    done
}
