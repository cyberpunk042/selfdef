#!/usr/bin/env bats
# L2 bats functional tests for the lynis-cron lynis-audit.sh wrapper.
#
# Wraps `lynis audit system`: reads the hardening_index from the report file
# and maps it to a severity (>=80 ok, 60-79 warn, <60 alert; report missing =
# high). Drives the wrapper with a fake `lynis` (no-op) + a controlled report
# file (SELFDEF_LYNIS_REPORT).
#
# Run with: bats packaging/test/L2-lynis-cron.bats

WD="${BATS_TEST_DIRNAME}/../../modules/lynis-cron/systemd/lynis-audit.sh"

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
    FAKE_LYNIS="${TMP}/lynis"
    printf '#!/usr/bin/env bash\nexit 0\n' > "${FAKE_LYNIS}"; chmod +x "${FAKE_LYNIS}"
    REPORT="${TMP}/lynis-report.dat"
}

teardown() { rm -rf "${TMP}"; }

mk_report() {  # hardening_index
    printf 'hardening_index=%s\nwarning[]=PERM-2904|World-writable file found|-|\nsuggestion[]=KRNL-5820|disable core dumps|-|\n' "$1" > "${REPORT}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_LYNIS_PROFILE="${PROFILE:-quick}" \
    SELFDEF_LYNIS_BIN="${FAKE_LYNIS}" \
    SELFDEF_LYNIS_REPORT="${REPORT_V:-$REPORT}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "report missing → high / report_missing" {
    REPORT_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"report_missing"'
    cap | grep -q '"severity":"high"'
}

@test "hardening_index >= 80 → ok / audit_ok" {
    mk_report 85
    run_wd
    cap | grep -q '"event":"audit_ok"'
    cap | grep -q '"severity":"ok"'
}

@test "hardening_index 60-79 → warn / hardening_moderate" {
    mk_report 72
    run_wd
    cap | grep -q '"event":"hardening_moderate"'
    cap | grep -q '"severity":"warn"'
}

@test "hardening_index < 60 → alert / hardening_low" {
    mk_report 48
    run_wd
    cap | grep -q '"event":"hardening_low"'
    cap | grep -q '"severity":"alert"'
}
