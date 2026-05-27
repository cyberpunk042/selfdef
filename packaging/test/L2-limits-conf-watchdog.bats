#!/usr/bin/env bats
# L2 bats functional tests for the limits-conf-watchdog scan script.
#
# /etc/security/limits.conf sets per-domain resource limits. A limit that
# re-enables core dumps (core != 0) can be abused to capture process memory
# (credentials/keys) on crash — a defense-impairment / credential-access
# signature. Severity:
#   ok    → no delta
#   warn  → any limit/file added/removed/changed
#   alert → a limit that re-enables core dumps
#
# Run with: bats packaging/test/L2-limits-conf-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd/limits-conf-watchdog.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SELFDEF_TEST_LOGCAP}"
FAKELOGGER
    chmod +x "${BIN}/logger"
    export SELFDEF_TEST_LOGCAP="${TMP}/log.out"
    : > "${SELFDEF_TEST_LOGCAP}"
    BASELINE="${TMP}/baseline.tsv"
    CONF="${TMP}/limits.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_LIMITS_PROFILE="${PROFILE:-report}" \
    SELFDEF_LIMITS_BASELINE="${BASELINE}" \
    SELFDEF_LIMITS_FILE="${CONF_V:-$CONF}" \
    SELFDEF_LIMITS_D="${TMP}/no-limits-d" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '* soft nofile 1024\n* hard core 0\n' > "${CONF}"
}

@test "no limits.conf → ok / no_limits_conf" {
    CONF_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_limits_conf"'
    cap | grep -q '"severity":"ok"'
}

@test "benign limits.conf, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged limits.conf on second run → ok / limits_conf_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"limits_conf_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a core-dump re-enable → alert / limits_conf_core_reenabled" {
    seed_benign
    run_wd
    printf '* soft nofile 1024\n* hard core unlimited\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"limits_conf_core_reenabled"'
    cap | grep -q '"severity":"alert"'
}

@test "a benign limit change → warn / limits_conf_changed" {
    seed_benign
    run_wd
    printf '* soft nofile 2048\n* hard core 0\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"limits_conf_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign limits.conf with core 0 is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "enforce profile exits non-zero on a core-dump re-enable" {
    seed_benign
    run_wd
    printf '* hard core unlimited\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
