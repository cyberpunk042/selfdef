#!/usr/bin/env bats
# L2 bats functional tests for the rsyslog-exec-watchdog scan script.
#
# rsyslog can run a program per log message — modern `omprog`
# (action(type="omprog" binary="/path")) or the legacy caret action
# (`<selector> ^program;template`) — AS ROOT, fired by any matching log
# event (a log-event-triggered exec surface). A binary under a writable
# root, relative-with-slash, bare, or carrying an injection pattern is alert.
#
# Runs the actual scan script with `logger` shadowed on PATH and the config
# in a tmp sandbox via SELFDEF_RSYSLOG_FILE / _D.
#
# Run with: bats packaging/test/L2-rsyslog-exec-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/rsyslog-exec-watchdog/systemd/rsyslog-exec-watchdog.sh"

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
    CONF="${TMP}/rsyslog.conf"
    CONFD="${TMP}/rsyslog.d"; mkdir -p "${CONFD}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_RSYSLOG_PROFILE="${PROFILE:-report}" \
    SELFDEF_RSYSLOG_BASELINE="${BASELINE}" \
    SELFDEF_RSYSLOG_FILE="${CONF_F:-$CONF}" \
    SELFDEF_RSYSLOG_D="${CONFD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no rsyslog config → ok / no_rsyslog" {
    CONF_F="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_rsyslog"'
    cap | grep -q '"severity":"ok"'
}

@test "benign omprog binary, first run → ok / baseline_initial" {
    printf 'module(load="omprog")\naction(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / rsyslog_exec_intact" {
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"rsyslog_exec_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "omprog binary under a writable root → alert / rsyslog_exec_suspicious" {
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd                                   # benign baseline
    printf 'action(type="omprog" binary="/tmp/.x")\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"rsyslog_exec_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a bare (non-absolute) omprog binary → alert" {
    # rsyslog omprog binaries are normally absolute; a bare name is abnormal.
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    printf 'action(type="omprog" binary="evilprog")\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a legacy caret action under a writable root → alert" {
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    printf '*.* ^/tmp/evil;RSYSLOG_TraditionalFileFormat\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign binary change → warn / rsyslog_exec_changed" {
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper2")\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"rsyslog_exec_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "a /usr/libexec omprog binary is NOT flagged" {
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "enforce profile exits non-zero on a suspicious binary" {
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    printf 'action(type="omprog" binary="/tmp/.x")\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
