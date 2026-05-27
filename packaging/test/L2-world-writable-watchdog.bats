#!/usr/bin/env bats
# L2 bats functional tests for the world-writable-watchdog scan script.
#
# A scan for world-writable (perm 0002) regular files + non-sticky
# world-writable dirs outside the sticky-scratch whitelist (/tmp, /var/tmp,
# /dev/shm, /run/lock). A world-writable file under a system root lets any
# local user tamper with it — a privilege-escalation / persistence stepping
# stone. Stateless count ladder:
#   ok    → 0 findings
#   warn  → 1..25 findings
#   alert → 26+ findings
#
# Runs the actual scan script with `logger` shadowed on PATH and a tmp
# scan-root via SELFDEF_WORLDWRITE_ROOTS.
#
# Run with: bats packaging/test/L2-world-writable-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd/world-writable-watchdog.sh"

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
    SELFDEF_WORLDWRITE_PROFILE="${PROFILE:-report}" \
    SELFDEF_WORLDWRITE_ROOTS="${ROOT}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "no world-writable files → ok / no_findings" {
    printf 'x' > "${ROOT}/normal"; chmod 0644 "${ROOT}/normal"
    run_wd
    cap | grep -q '"event":"no_findings"'
    cap | grep -q '"severity":"ok"'
}

@test "one world-writable file → warn / world_writable_found" {
    printf 'x' > "${ROOT}/loose"; chmod 0666 "${ROOT}/loose"
    run_wd
    cap | grep -q '"event":"world_writable_found"'
    cap | grep -q '"severity":"warn"'
}

@test "a normal 0644 file is NOT flagged" {
    printf 'x' > "${ROOT}/normal"; chmod 0644 "${ROOT}/normal"
    run_wd
    cap | grep -q '"severity":"ok"'
    ! cap | grep -q '"severity":"warn"'
}

@test "26+ world-writable files → alert / bulk_world_writable" {
    for i in $(seq 1 30); do printf 'x' > "${ROOT}/ww${i}"; chmod 0666 "${ROOT}/ww${i}"; done
    run_wd
    cap | grep -q '"event":"bulk_world_writable"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a world-writable finding" {
    printf 'x' > "${ROOT}/loose"; chmod 0666 "${ROOT}/loose"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
}
