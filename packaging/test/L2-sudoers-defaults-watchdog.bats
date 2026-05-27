#!/usr/bin/env bats
# L2 bats functional tests for the sudoers-defaults-watchdog scan script.
#
# `Defaults` lines in /etc/sudoers{,.d} shape EVERY sudo invocation. Three
# high-signal classes turn sudo into a privilege-escalation primitive:
#   - secure_path with a writable/tmp/home/relative element (sudo resolves
#     a trojan binary from there);
#   - env_keep/env_check/env_delete of a dangerous var (LD_PRELOAD,
#     LD_LIBRARY_PATH, BASH_ENV, …) surviving into the root command;
#   - !env_reset (the whole caller environment survives into sudo).
#
# Runs the actual scan script with `logger` shadowed on PATH and the
# sudoers file/dir + baseline in a tmp sandbox via SELFDEF_SUDODEF_*.
#
# Run with: bats packaging/test/L2-sudoers-defaults-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/sudoers-defaults-watchdog/systemd/sudoers-defaults-watchdog.sh"
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
    SUDOERS="${TMP}/sudoers"
    SUDOERSD="${TMP}/sudoers.d"; mkdir -p "${SUDOERSD}"
    BENIGN='Defaults secure_path="/usr/sbin:/usr/bin:/sbin:/bin"
Defaults env_reset
Defaults requiretty
'
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_SUDODEF_PROFILE="${PROFILE:-report}" \
    SELFDEF_SUDODEF_BASELINE="${BASELINE}" \
    SELFDEF_SUDODEF_FILE="${SUDOERS_F:-$SUDOERS}" \
    SELFDEF_SUDODEF_D="${SUDOERSD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no sudoers present → ok / no_sudoers" {
    SUDOERS_F="${TMP}/nonexistent" SUDOERSD="${TMP}/nonexistent.d" run_wd
    cap | grep -q '"event":"no_sudoers"'
    cap | grep -q '"severity":"ok"'
}

@test "benign Defaults, first run → ok / baseline_initial" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged sudoers on second run → ok / sudoers_defaults_intact" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"sudoers_defaults_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — dangerous Defaults
# ============================================================

@test "secure_path containing /tmp → alert / sudoers_defaults_dangerous" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd                                   # benign baseline
    printf 'Defaults secure_path="/usr/bin:/tmp"\nDefaults env_reset\n' > "${SUDOERS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"sudoers_defaults_dangerous"'
    cap | grep -q '"severity":"alert"'
}

@test "env_keep of LD_PRELOAD → alert" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    printf '%sDefaults env_keep += "LD_PRELOAD"\n' "${BENIGN}" > "${SUDOERS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "!env_reset → alert" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    printf 'Defaults secure_path="/usr/bin:/bin"\nDefaults !env_reset\n' > "${SUDOERS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "secure_path with a relative element → alert" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    printf 'Defaults secure_path="/usr/bin:bin"\nDefaults env_reset\n' > "${SUDOERS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign Defaults change → warn / sudoers_defaults_changed" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    printf '%sDefaults timestamp_timeout=15\n' "${BENIGN}" > "${SUDOERS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"sudoers_defaults_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "a standard secure_path + env_reset is NOT flagged" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "env_keep of a non-dangerous var (EDITOR) is NOT flagged" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    printf '%sDefaults env_keep += "EDITOR"\n' "${BENIGN}" > "${SUDOERS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
}

# ============================================================
# enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a dangerous default" {
    printf '%s' "${BENIGN}" > "${SUDOERS}"
    run_wd
    printf 'Defaults secure_path="/usr/bin:/tmp"\n' > "${SUDOERS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
