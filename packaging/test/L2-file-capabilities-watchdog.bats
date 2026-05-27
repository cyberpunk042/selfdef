#!/usr/bin/env bats
# L2 bats functional tests for the file-capabilities-watchdog scan script.
#
# A baseline delta of file capabilities (security.capability xattr, set via
# setcap). A binary granted a capability gains a slice of root power without
# the setuid bit — e.g. cap_setuid is full uid control, cap_dac_override
# bypasses all permission checks (T1548). Severity on the delta:
#   ok    → no delta
#   warn  → 1..2 added capability binaries
#   alert → 3+ added, OR any added binary with a "dangerous" capability
#           (setuid/setgid/dac_override/dac_read_search/sys_admin/
#            sys_ptrace/sys_module)
#
# Tests use setcap, so they require root + an xattr-capable fs (true in the
# CI/root sandbox; verified at setup).
#
# Run with: bats packaging/test/L2-file-capabilities-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd/file-capabilities-watchdog.sh"

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
    ROOT="${TMP}/scan"; mkdir -p "${ROOT}"
    # Skip the whole suite if the tmp fs cannot hold capability xattrs.
    printf '#!/bin/sh\n' > "${ROOT}/.probe"; chmod 0755 "${ROOT}/.probe"
    setcap cap_net_raw+ep "${ROOT}/.probe" 2>/dev/null || skip "fs does not support capability xattrs"
    rm -f "${ROOT}/.probe"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_FILECAPS_PROFILE="${PROFILE:-report}" \
    SELFDEF_FILECAPS_ROOTS="${ROOT}" \
    SELFDEF_FILECAPS_BASELINE="${BASELINE}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

mk_cap() { printf '#!/bin/sh\n' > "${ROOT}/$1"; chmod 0755 "${ROOT}/$1"; setcap "$2" "${ROOT}/$1"; }

@test "first run with one cap binary → ok / baseline_initial" {
    mk_cap ping cap_net_raw+ep
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged caps on second run → ok / no_delta" {
    mk_cap ping cap_net_raw+ep
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
}

@test "one added non-dangerous cap binary → warn / capability_added" {
    mk_cap ping cap_net_raw+ep
    run_wd
    mk_cap webserver cap_net_bind_service+ep
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"capability_added"'
    cap | grep -q '"severity":"warn"'
}

@test "three added cap binaries → alert / mass_capability_added" {
    mk_cap ping cap_net_raw+ep
    run_wd
    mk_cap a1 cap_net_bind_service+ep
    mk_cap a2 cap_net_bind_service+ep
    mk_cap a3 cap_net_bind_service+ep
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"mass_capability_added"'
    cap | grep -q '"severity":"alert"'
}

@test "an added binary with a dangerous capability → alert / dangerous_capability_added" {
    mk_cap ping cap_net_raw+ep
    run_wd
    mk_cap backdoor cap_setuid+ep
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dangerous_capability_added"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on an added cap binary" {
    mk_cap ping cap_net_raw+ep
    run_wd
    mk_cap webserver cap_net_bind_service+ep
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
}
