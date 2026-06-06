#!/usr/bin/env bats
# L2 bats functional tests for the rkhunter-cron rkhunter-check.sh wrapper.
#
# Wraps `rkhunter --check`: maps its exit code to a severity (0 ok, 1 warn,
# 2 alert/errors, other alert/runtime_issue). Drives the wrapper with a fake
# `rkhunter` (SELFDEF_RKHUNTER_BIN) emitting controlled warnings + exit code.
#
# Run with: bats packaging/test/L2-rkhunter-cron.bats

WD="${BATS_TEST_DIRNAME}/../../modules/rkhunter-cron/systemd/rkhunter-check.sh"

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
    FAKE_RK="${TMP}/rkhunter"
}

teardown() { rm -rf "${TMP}"; }

# mk_rk <rc> <stdout>
mk_rk() {
    { printf '#!/usr/bin/env bash\n'; printf 'cat <<'\''OUT'\''\n%s\nOUT\n' "$2"; printf 'exit %s\n' "$1"; } > "${FAKE_RK}"
    chmod +x "${FAKE_RK}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_RKHUNTER_PROFILE="${PROFILE:-report}" \
    SELFDEF_RKHUNTER_BIN="${FAKE_RK}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "clean check (rc 0) → ok / no_findings" {
    mk_rk 0 "System checks summary: no warnings"
    run_wd
    cap | grep -q '"event":"no_findings"'
    cap | grep -q '"severity":"ok"'
}

@test "warnings (rc 1) → warn / warnings_found" {
    mk_rk 1 "Warning: Suspicious file /dev/.hidden
Warning: Hidden directory found"
    run_wd
    cap | grep -q '"event":"warnings_found"'
    cap | grep -q '"severity":"warn"'
}

@test "errors (rc 2) → alert / errors_found" {
    mk_rk 2 "Error: config problem"
    run_wd
    cap | grep -q '"event":"errors_found"'
    cap | grep -q '"severity":"alert"'
}

@test "runtime issue (rc >2) → alert / runtime_issue" {
    mk_rk 5 "rkhunter: database outdated"
    run_wd
    cap | grep -q '"event":"runtime_issue"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on warnings" {
    mk_rk 1 "Warning: Suspicious file /dev/.hidden"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"warn"'
}

@test "warning count surfaces in JSON (operator triage)" {
    mk_rk 1 "Warning: Suspicious file /dev/.hidden
Warning: Hidden directory found
Warning: Third warning"
    run_wd
    cap | grep -q '"warning_count":3'
}

@test "warning sample (up to 5 lines) surfaces in 'sample' field for operator triage" {
    mk_rk 1 "Warning: Suspicious file /dev/.hidden
Warning: Hidden directory found"
    run_wd
    cap | grep -q 'Suspicious file'
}

@test "profile field surfaces in JSON (echo of operator-set profile)" {
    mk_rk 0 "System checks summary: no warnings"
    PROFILE=report run_wd
    cap | grep -q '"profile":"report"'
}

@test "rkhunter rc surfaces in JSON (operator can see the raw exit code)" {
    mk_rk 1 "Warning: x"
    run_wd
    cap | grep -q '"rkhunter_rc":1'
}

@test "JSON record is emitted as a SINGLE logger line (downstream JSON-line consumer contract)" {
    mk_rk 0 "System checks summary: no warnings"
    run_wd
    n=$(cap | grep -c '"tag":"selfdef-rkhunter"')
    [ "${n}" = "1" ]
}

@test "report profile exits 0 even on alert severity (findings are advisory)" {
    mk_rk 2 "Error: config problem"
    PROFILE=report run run_wd
    [ "${status}" = "0" ]
    cap | grep -q '"severity":"alert"'
}

@test "report profile exits 0 even on warn severity (warnings are advisory)" {
    mk_rk 1 "Warning: x"
    PROFILE=report run run_wd
    [ "${status}" = "0" ]
}
