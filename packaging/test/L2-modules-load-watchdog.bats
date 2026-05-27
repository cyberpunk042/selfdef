#!/usr/bin/env bats
# L2 bats functional tests for the modules-load-watchdog scan script.
#
# /etc/modules-load.d/*.conf (and /etc/modules) lists kernel modules to load
# at boot. A world-writable / non-root config lets any user queue an
# arbitrary module load at next boot (T1547.006 kernel-module persistence).
# Severity:
#   ok    → no delta
#   warn  → a module-to-load added/removed, or a file changed
#   alert → a config file world-writable or non-root-owned
#
# Run with: bats packaging/test/L2-modules-load-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/modules-load-watchdog/systemd/modules-load-watchdog.sh"

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
    CONFD="${TMP}/modules-load.d"; mkdir -p "${CONFD}"
    CONF="${CONFD}/net.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODLOAD_PROFILE="${PROFILE:-report}" \
    SELFDEF_MODLOAD_BASELINE="${BASELINE}" \
    SELFDEF_MODLOAD_DIRS="${DIRS_V:-$CONFD}" \
    SELFDEF_MODLOAD_ETC_MODULES="${TMP}/no-etc-modules" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf 'overlay\nbr_netfilter\n' > "${CONF}"
}

@test "no modules-load config → ok / no_modules_load" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_modules_load"'
    cap | grep -q '"severity":"ok"'
}

@test "benign modules-load conf, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged modules-load conf on second run → ok / modules_load_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"modules_load_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a world-writable config → alert / modules_load_writable_config" {
    seed_benign
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"modules_load_writable_config"'
    cap | grep -q '"severity":"alert"'
}

@test "a benign module-to-load change → warn / modules_load_changed" {
    seed_benign
    run_wd
    printf 'overlay\nbr_netfilter\nip_tables\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"modules_load_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned config is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "enforce profile exits non-zero on a world-writable config" {
    seed_benign
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
