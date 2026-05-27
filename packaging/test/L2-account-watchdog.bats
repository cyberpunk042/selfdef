#!/usr/bin/env bats
# L2 capture-regression test for the account-watchdog scan script.
#
# account-watchdog inventories every /etc/passwd entry + the sudo/wheel/admin
# roster into a baseline, then alerts on a new account / new uid-0 / new
# privileged-group member. It reads /etc/passwd + getent directly (NO
# input-source knob), so the FINDING tiers (new_account /
# new_privileged_account) are not hermetically testable here — that would
# need a passwd-source knob or mutating the real account DB. What IS testable,
# and what this suite locks, is the inventory-CAPTURE regression: the scan
# must actually write its records into the baseline it diffs.
#
# (Regression guard for the 2026-05-27 bug where the inventory printfs went to
# stdout instead of the $current temp file, so the baseline was always empty
# and the watchdog never detected a new root account — fixed at the root.)
#
# Run with: bats packaging/test/L2-account-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd/account-watchdog.sh"

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
    BASELINE="${TMP}/accounts-baseline.tsv"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_ACCOUNTS_PROFILE="${PROFILE:-report}" \
    SELFDEF_ACCOUNTS_BASELINE="${BASELINE}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "first run captures the account inventory into the baseline (non-empty)" {
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
    [ -s "${BASELINE}" ]                          # NON-EMPTY = the bug-fix regression lock
    grep -q '^user	' "${BASELINE}"               # real passwd entries were recorded
}

@test "the baseline records the root uid-0 entry" {
    run_wd
    grep -q '^uid0	root' "${BASELINE}"           # root captured — the privesc surface the watchdog guards
}

@test "unchanged accounts on second run → ok / no_delta" {
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
}
