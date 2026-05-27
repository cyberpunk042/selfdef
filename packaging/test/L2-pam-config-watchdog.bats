#!/usr/bin/env bats
# L2 capture-regression test for the pam-config-watchdog scan script.
#
# pam-config-watchdog inventories the /etc/pam.d rule lines + the pam_*.so
# module hashes into a baseline, then alerts on a PAM-stack change (a new
# module / control change = an auth-bypass surface). It reads /etc/pam.d +
# the standard security lib dirs directly (NO input-source knob), so the
# change/removed FINDING tiers are not hermetically testable here. What IS
# testable, and what this suite locks, is the inventory-CAPTURE regression.
#
# (Regression guard for the 2026-05-27 bug where the inventory printfs went to
# stdout instead of the $current temp file, so the baseline was always empty
# and the watchdog never detected PAM-stack tampering — fixed at the root.)
#
# Requires a populated /etc/pam.d (skips otherwise).
#
# Run with: bats packaging/test/L2-pam-config-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/pam-config-watchdog/systemd/pam-config-watchdog.sh"

setup() {
    [ -d /etc/pam.d ] && [ -n "$(ls -A /etc/pam.d 2>/dev/null)" ] || skip "no populated /etc/pam.d on this host"
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SELFDEF_TEST_LOGCAP}"
FAKELOGGER
    chmod +x "${BIN}/logger"
    export SELFDEF_TEST_LOGCAP="${TMP}/log.out"
    : > "${SELFDEF_TEST_LOGCAP}"
    BASELINE="${TMP}/pam-baseline.tsv"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_PAMCFG_PROFILE="${PROFILE:-report}" \
    SELFDEF_PAMCFG_BASELINE="${BASELINE}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "first run captures the PAM inventory into the baseline (non-empty)" {
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    [ -f "${BASELINE}" ]
    [ -s "${BASELINE}" ]                          # NON-EMPTY = the bug-fix regression lock
    grep -qE '^(pamline|pammod)	' "${BASELINE}"  # real pam.d rules / module hashes recorded
}

@test "unchanged PAM stack on second run → ok / no_delta" {
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
}
