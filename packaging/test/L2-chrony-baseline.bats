#!/usr/bin/env bats
# L2 functional suite for chrony-baseline.
#
# chrony-baseline installs an /etc/chrony/conf.d/50-selfdef.conf
# drop-in that pins chrony to a known-good NTP profile:
#   pool → Debian/RHEL pool servers
#   nts  → NTS (Network Time Security — authenticated NTP, the
#          stronger choice when the network may be hostile)
#
# Time integrity is a security control: clock manipulation breaks
# certificate validity, enables TOTP replay, evades log
# correlation. A canonical clock-source pin is the foundation.
#
# CRITICAL INVARIANTS:
#   - Idempotent: byte-identical re-install is a no-op (no
#     systemctl restart fired).
#   - DRY_RUN protects /etc/chrony/conf.d + systemctl restart.
#   - Profile downgrade nts → pool replaces the drop-in.
#
# Uses SELFDEF_CHRONY_DROPIN_DIR + SELFDEF_CHRONY_BASELINE_CONFIGS
# env-vars (already present) for L2 testability.
#
# Run with: bats packaging/test/L2-chrony-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/chrony-baseline/install/apply.sh"

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
    CONF="${TMP}/chrony-baseline.toml"
    CONFIGS_SRC="${TMP}/configs"
    CHRONY_DROPIN_DIR="${TMP}/chrony.conf.d"
    mkdir -p "${CONFIGS_SRC}" "${CHRONY_DROPIN_DIR}"
    # Fixture source profiles.
    cat > "${CONFIGS_SRC}/pool.conf" <<'POOLEOF'
pool 2.debian.pool.ntp.org iburst
makestep 1.0 3
rtcsync
POOLEOF
    cat > "${CONFIGS_SRC}/nts.conf" <<'NTSEOF'
server time.cloudflare.com nts iburst
server time.nist.gov nts iburst
makestep 1.0 3
rtcsync
NTSEOF
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_CHRONY_BASELINE_CONFIG="${CONF}" \
    SELFDEF_CHRONY_BASELINE_CONFIGS="${CONFIGS_SRC}" \
    SELFDEF_CHRONY_DROPIN_DIR="${CHRONY_DROPIN_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_CHRONY_BASELINE_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_CHRONY_BASELINE_CONFIG="${SELFDEF_CHRONY_BASELINE_CONFIG}" \
        SELFDEF_CHRONY_BASELINE_CONFIGS="${CONFIGS_SRC}" \
        SELFDEF_CHRONY_DROPIN_DIR="${CHRONY_DROPIN_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "missing config source dir → die" {
    write_config "pool"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_CHRONY_BASELINE_CONFIG="${CONF}" \
        SELFDEF_CHRONY_BASELINE_CONFIGS="${TMP}/missing-src" \
        SELFDEF_CHRONY_DROPIN_DIR="${CHRONY_DROPIN_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config source dir missing"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_CHRONY_BASELINE_CONFIG="${CONF}" \
        SELFDEF_CHRONY_BASELINE_CONFIGS="${CONFIGS_SRC}" \
        SELFDEF_CHRONY_DROPIN_DIR="${CHRONY_DROPIN_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be pool|nts"* ]]
}

@test "pool profile installs the drop-in + restarts chronyd" {
    write_config "pool"
    run_wd
    [ -f "${CHRONY_DROPIN_DIR}/50-selfdef.conf" ]
    cmp -s "${CONFIGS_SRC}/pool.conf" "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    grep -q 'systemctl restart chronyd' "${SYSEOF_LOG}"
}

@test "nts profile installs the NTS-authenticated drop-in" {
    write_config "nts"
    run_wd
    [ -f "${CHRONY_DROPIN_DIR}/50-selfdef.conf" ]
    cmp -s "${CONFIGS_SRC}/nts.conf" "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    # NTS keyword present in installed drop-in.
    grep -q 'nts' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT: idempotent — re-install with identical content is a no-op (no chronyd restart fired)" {
    write_config "pool"
    run_wd                              # initial install
    : > "${SYSEOF_LOG}"                 # clear log
    run_wd                              # re-install — identical
    ! grep -q 'systemctl restart' "${SYSEOF_LOG}"
}

@test "INVARIANT: profile downgrade nts → pool replaces drop-in + restarts" {
    write_config "nts"
    run_wd
    grep -q 'nts' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    write_config "pool"
    : > "${SYSEOF_LOG}"
    run_wd
    ! grep -q 'nts' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    grep -q 'pool' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    grep -q 'systemctl restart' "${SYSEOF_LOG}"
}

@test "INVARIANT: DRY_RUN does not install drop-in or restart" {
    write_config "pool"
    DRY_RUN=1 run_wd
    ! [ -f "${CHRONY_DROPIN_DIR}/50-selfdef.conf" ]
    ! grep -q 'systemctl restart' "${SYSEOF_LOG}"
}

@test "default profile is pool (no profile key)" {
    : > "${CONF}"
    run_wd
    cmp -s "${CONFIGS_SRC}/pool.conf" "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
}

@test "drop-in is chmod 0644 (system-config convention for /etc/chrony/conf.d)" {
    write_config "pool"
    run_wd
    perms="$(stat -c '%a' "${CHRONY_DROPIN_DIR}/50-selfdef.conf")"
    [ "${perms}" = "644" ]
}

@test "INVARIANT (idempotent mtime): byte-identical re-install preserves mtime (not just no-restart)" {
    # Stronger than test-122's "no restart" — locks the file-mtime
    # preservation that the cmp -s guard provides.
    write_config "pool"
    run_wd
    mtime_before="$(stat -c '%Y' "${CHRONY_DROPIN_DIR}/50-selfdef.conf")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${CHRONY_DROPIN_DIR}/50-selfdef.conf")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT (profile upgrade pool → nts): replaces drop-in + fires restart" {
    # The reverse direction of test-130 (nts → pool). Both
    # transitions must work — locks the bidirectional contract.
    write_config "pool"
    run_wd
    grep -q 'pool' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    write_config "nts"
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'nts' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    ! grep -q '^pool ' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    grep -q 'systemctl restart' "${SYSEOF_LOG}"
}

@test "INVARIANT (no render-timestamp in drop-in): chrony drop-in must not carry a Generated <ISO-date> line" {
    write_config "pool"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (NTS profile carries cloudflare + nist server lines): both authenticated servers surface in drop-in" {
    write_config "nts"
    run_wd
    grep -q 'time.cloudflare.com' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    grep -q 'time.nist.gov' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
}

@test "emit_status surfaces profile + result in JSON (operator observability)" {
    write_config "pool"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"chrony-baseline"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=pool'* ]]
}
