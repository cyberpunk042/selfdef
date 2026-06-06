#!/usr/bin/env bats
# L2 functional suite for acct-baseline.
#
# acct-baseline provisions process accounting (BSD-style acct):
#   - Creates /var/account/ + pacct file (mode 0640 root:root)
#   - Installs a logrotate drop-in to roll pacct daily/weekly
#   - enabled profile: accton on /var/account/pacct + enables
#     acct.service / psacct.service (distro-dependent)
#   - disabled profile: accton off + leaves the logrotate drop-
#     in installed (operator can re-enable later without
#     re-touching the rotate config)
#
# Adds SELFDEF_ACCT_DIR + SELFDEF_PACCT_FILE + SELFDEF_LOGROTATE_DIR
# env-var overrides for L2 testability (ACCT_DIR added 2026-06-06).
# Live defaults unchanged.
#
# Run with: bats packaging/test/L2-acct-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/accton" <<'ACEOF'
#!/usr/bin/env bash
printf 'accton %s\n' "$*" >> "${ACCT_LOG}"
exit 0
ACEOF
    chmod +x "${BIN}/accton"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    export ACCT_LOG="${TMP}/accton.log"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${ACCT_LOG}"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/acct-baseline.toml"
    ACCT_DIR="${TMP}/account"
    PACCT_FILE="${ACCT_DIR}/pacct"
    LOGROTATE_DIR="${TMP}/logrotate.d"
    LOGROTATE_DST="${LOGROTATE_DIR}/selfdef-acct"
    mkdir -p "${LOGROTATE_DIR}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    ACCT_LOG="${ACCT_LOG}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_ACCT_CONFIG="${CONF}" \
    SELFDEF_ACCT_DIR="${ACCT_DIR}" \
    SELFDEF_PACCT_FILE="${PACCT_FILE}" \
    SELFDEF_LOGROTATE_DIR="${LOGROTATE_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_ACCT_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_ACCT_CONFIG="${SELFDEF_ACCT_CONFIG}" \
        SELFDEF_ACCT_DIR="${ACCT_DIR}" \
        SELFDEF_PACCT_FILE="${PACCT_FILE}" \
        SELFDEF_LOGROTATE_DIR="${LOGROTATE_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_ACCT_CONFIG="${CONF}" \
        SELFDEF_ACCT_DIR="${ACCT_DIR}" \
        SELFDEF_PACCT_FILE="${PACCT_FILE}" \
        SELFDEF_LOGROTATE_DIR="${LOGROTATE_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be enabled|disabled"* ]]
}

@test "enabled profile creates ACCT_DIR + pacct file + installs logrotate drop-in" {
    write_config "enabled"
    run_wd
    [ -d "${ACCT_DIR}" ]
    [ -f "${PACCT_FILE}" ]
    [ -f "${LOGROTATE_DST}" ]
}

@test "enabled profile fires accton on <pacct> AND enables the OS service" {
    write_config "enabled"
    run_wd
    grep -qE "accton ${PACCT_FILE}" "${ACCT_LOG}"
    # Tries acct.service first; falls back to psacct (distro-aware).
    grep -qE 'systemctl enable --now (acct|psacct)' "${SYSEOF_LOG}"
}

@test "disabled profile fires accton off (no <pacct> arg) AND does NOT touch the OS service" {
    write_config "disabled"
    run_wd
    grep -q 'accton off' "${ACCT_LOG}"
    ! grep -q 'systemctl enable' "${SYSEOF_LOG}"
}

@test "disabled profile STILL installs the logrotate drop-in (operator-pull re-enable)" {
    write_config "disabled"
    run_wd
    [ -f "${LOGROTATE_DST}" ]
}

@test "logrotate drop-in is chmod 0644 (system-config convention)" {
    write_config "enabled"
    run_wd
    [ "$(stat -c '%a' "${LOGROTATE_DST}")" = "644" ]
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite logrotate drop-in" {
    write_config "enabled"
    run_wd
    [ -f "${LOGROTATE_DST}" ]
    mtime_before="$(stat -c '%Y' "${LOGROTATE_DST}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${LOGROTATE_DST}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: profile switch enabled → disabled changes accton arg + leaves logrotate drop-in intact" {
    write_config "enabled"
    run_wd
    [ -f "${LOGROTATE_DST}" ]
    logrotate_mtime_before="$(stat -c '%Y' "${LOGROTATE_DST}")"
    : > "${ACCT_LOG}"
    sleep 1
    write_config "disabled"
    run_wd
    grep -q 'accton off' "${ACCT_LOG}"
    [ -f "${LOGROTATE_DST}" ]
    # logrotate file unchanged (no re-install needed across profile switch).
    logrotate_mtime_after="$(stat -c '%Y' "${LOGROTATE_DST}")"
    [ "${logrotate_mtime_before}" = "${logrotate_mtime_after}" ]
}

@test "INVARIANT: DRY_RUN does not write pacct, logrotate drop-in, or fire accton/systemctl" {
    write_config "enabled"
    DRY_RUN=1 run_wd
    ! [ -f "${PACCT_FILE}" ]
    ! [ -f "${LOGROTATE_DST}" ]
    ! grep -q 'accton' "${ACCT_LOG}"
    ! grep -q 'systemctl' "${SYSEOF_LOG}"
}

@test "default profile is enabled (no profile key — captures process accounting by default)" {
    : > "${CONF}"
    run_wd
    [ -f "${PACCT_FILE}" ]
    grep -qE "accton ${PACCT_FILE}" "${ACCT_LOG}"
}

@test "emit_status reports changes count + pacct path in JSON" {
    write_config "enabled"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'changes=1'* ]]
    [[ "${output}" == *"pacct=${PACCT_FILE}"* ]]
    # Second apply: logrotate unchanged → changes=0.
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'changes=0'* ]]
}

@test "INVARIANT (profile reverse disabled → enabled): fires accton on + re-enables service" {
    write_config "disabled"
    run_wd
    : > "${ACCT_LOG}"
    : > "${SYSEOF_LOG}"
    write_config "enabled"
    run_wd
    grep -qE "accton ${PACCT_FILE}" "${ACCT_LOG}"
    grep -qE 'systemctl enable --now (acct|psacct)' "${SYSEOF_LOG}"
}

@test "INVARIANT (pacct file chmod 0640 — root + adm-group readable, NOT world-readable)" {
    # pacct contains process-history with command names + args + exit
    # codes — sensitive on a multi-user system. Lock 0640.
    write_config "enabled"
    run_wd
    [ "$(stat -c '%a' "${PACCT_FILE}")" = "640" ]
}

@test "INVARIANT (ACCT_DIR chmod 0750 — root + adm-group can list, NOT world-listable)" {
    write_config "enabled"
    run_wd
    [ "$(stat -c '%a' "${ACCT_DIR}")" = "750" ]
}

@test "INVARIANT (logrotate drop-in references /var/account/pacct — the canonical pacct path)" {
    # The drop-in is shipped as a fixture (modules/acct-baseline/systemd/
    # selfdef-acct.logrotate) with /var/account/pacct hard-coded. This
    # is intentional: logrotate config refs the canonical live path, not
    # the (test-overridable) PACCT_FILE env var.
    write_config "enabled"
    run_wd
    grep -q '/var/account/pacct' "${LOGROTATE_DST}"
}

@test "INVARIANT (logrotate drop-in carries the actual rotate directive)" {
    write_config "enabled"
    run_wd
    grep -qE '^[[:space:]]*(daily|weekly|monthly)' "${LOGROTATE_DST}"
}

@test "INVARIANT (no render-timestamp in logrotate drop-in): defeats cmp -s idempotency" {
    write_config "enabled"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${LOGROTATE_DST}"
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates pacct file + ACCT_DIR + logrotate drop-in)" {
    write_config "enabled"
    run_wd
    [ -f "${PACCT_FILE}" ]
    [ -d "${ACCT_DIR}" ]
    [ -f "${LOGROTATE_DST}" ]
    rm -rf "${ACCT_DIR}"
    rm -f "${LOGROTATE_DST}"
    run_wd
    [ -d "${ACCT_DIR}" ]
    [ -f "${PACCT_FILE}" ]
    [ -f "${LOGROTATE_DST}" ]
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "enabled"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"acct-baseline"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=enabled'* ]]
}

@test "INVARIANT (logrotate drop-in carries compress + missingok + notifempty — operator-standard rotation directives)" {
    # The drop-in must implement proper rotation safety:
    # compress (saves disk), missingok (no rotate-bail if log absent),
    # notifempty (skip zero-byte rotations). Lock against rotation-
    # config drift to operator-unfriendly defaults.
    write_config "enabled"
    run_wd
    grep -qE 'compress' "${LOGROTATE_DST}"
    grep -qE 'missingok' "${LOGROTATE_DST}"
    grep -qE 'notifempty' "${LOGROTATE_DST}"
}
