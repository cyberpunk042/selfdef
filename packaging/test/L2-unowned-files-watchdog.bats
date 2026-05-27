#!/usr/bin/env bats
# L2 bats functional tests for the unowned-files-watchdog scan script.
#
# A scan for files whose uid or gid does not resolve to a passwd/group entry.
# Unowned files often appear after a user is deleted but their files linger
# (a re-created uid then inherits them) or after sloppy archive extraction —
# a privilege/ownership-confusion surface. Stateless count ladder:
#   ok    → 0 unowned
#   warn  → 1..50 unowned
#   alert → 51+ unowned (typical of a bulk uid-deletion incident)
#
# Tests chown files to an unresolved uid/gid, so they must run as root (true
# in the CI/root sandbox).
#
# Run with: bats packaging/test/L2-unowned-files-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd/unowned-files-watchdog.sh"

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
    ROOT="${TMP}/scan"; mkdir -p "${ROOT}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_UNOWNED_PROFILE="${PROFILE:-report}" \
    SELFDEF_UNOWNED_ROOTS="${ROOT}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "no unowned files → ok / no_unowned" {
    printf 'x' > "${ROOT}/owned"            # root-owned, resolvable
    run_wd
    cap | grep -q '"event":"no_unowned"'
    cap | grep -q '"severity":"ok"'
}

@test "one unowned file → warn / unowned_found" {
    printf 'x' > "${ROOT}/orphan"; chown 99999:99999 "${ROOT}/orphan"
    run_wd
    cap | grep -q '"event":"unowned_found"'
    cap | grep -q '"severity":"warn"'
}

@test "a normally-owned file is NOT flagged" {
    printf 'x' > "${ROOT}/owned"
    run_wd
    cap | grep -q '"severity":"ok"'
    ! cap | grep -q '"severity":"warn"'
}

@test "51+ unowned files → alert / bulk_unowned" {
    for i in $(seq 1 55); do printf 'x' > "${ROOT}/orphan${i}"; chown 99999:99999 "${ROOT}/orphan${i}"; done
    run_wd
    cap | grep -q '"event":"bulk_unowned"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on an unowned finding" {
    printf 'x' > "${ROOT}/orphan"; chown 99999:99999 "${ROOT}/orphan"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
}
