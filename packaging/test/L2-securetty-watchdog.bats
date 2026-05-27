#!/usr/bin/env bats
# L2 bats functional tests for the securetty-watchdog scan script.
#
# /etc/securetty is the allowlist of TTYs on which DIRECT root login is
# permitted (pam_securetty). Adding a network pty (pts/0) widens root login
# to network sessions; removing the file fail-opens root login on ALL ttys.
# Severity:
#   ok    → no delta
#   warn  → a TTY added/removed or file changed
#   alert → a newly-added pts/network TTY, a world-writable/non-root file, or
#           the file removed since baseline (fail-open)
#
# Run with: bats packaging/test/L2-securetty-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/securetty-watchdog/systemd/securetty-watchdog.sh"

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
    SECURETTY="${TMP}/securetty"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_SECURETTY_PROFILE="${PROFILE:-report}" \
    SELFDEF_SECURETTY_BASELINE="${BASELINE}" \
    SELFDEF_SECURETTY_FILE="${SECURETTY}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf 'tty1\ntty2\nttyS0\n' > "${SECURETTY}"
}

@test "no securetty + no baseline → ok / no_securetty" {
    run_wd
    cap | grep -q '"event":"no_securetty"'
    cap | grep -q '"severity":"ok"'
}

@test "benign securetty, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged securetty on second run → ok / securetty_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"securetty_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a newly-added pts TTY → alert / securetty_widened" {
    seed_benign
    run_wd
    printf 'tty1\ntty2\nttyS0\npts/0\n' > "${SECURETTY}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"securetty_widened"'
    cap | grep -q '"severity":"alert"'
}

@test "the file removed since baseline → alert / securetty_removed (fail-open)" {
    seed_benign
    run_wd
    rm -f "${SECURETTY}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"securetty_removed"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable securetty → alert" {
    seed_benign
    run_wd
    chmod 0666 "${SECURETTY}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign physical-tty addition → warn / securetty_changed" {
    seed_benign
    run_wd
    printf 'tty1\ntty2\nttyS0\ntty3\n' > "${SECURETTY}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"securetty_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "enforce profile exits non-zero on a widened securetty" {
    seed_benign
    run_wd
    printf 'tty1\ntty2\nttyS0\npts/0\n' > "${SECURETTY}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
