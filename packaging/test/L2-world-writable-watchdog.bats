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

@test "boundary: 25 world-writable files → warn (the 1..25 range is INCLUSIVE on the high end)" {
    for i in $(seq 1 25); do printf 'x' > "${ROOT}/ww${i}"; chmod 0666 "${ROOT}/ww${i}"; done
    run_wd
    cap | grep -q '"event":"world_writable_found"'
    cap | grep -q '"severity":"warn"'
}

@test "boundary: 26 world-writable files → alert (just over the warn ceiling)" {
    for i in $(seq 1 26); do printf 'x' > "${ROOT}/ww${i}"; chmod 0666 "${ROOT}/ww${i}"; done
    run_wd
    cap | grep -q '"event":"bulk_world_writable"'
    cap | grep -q '"severity":"alert"'
}

@test "finding_count surfaces in JSON (operator triage observability)" {
    for i in $(seq 1 7); do printf 'x' > "${ROOT}/ww${i}"; chmod 0666 "${ROOT}/ww${i}"; done
    run_wd
    cap | grep -q '"finding_count":7'
}

@test "sample of world-writable paths (up to 10) surfaces in 'sample' field for operator triage" {
    printf 'x' > "${ROOT}/very-distinctive-loose-name"; chmod 0666 "${ROOT}/very-distinctive-loose-name"
    run_wd
    cap | grep -q 'very-distinctive-loose-name'
}

@test "scan_roots field echoes the configured SELFDEF_WORLDWRITE_ROOTS (operator can verify the scan scope)" {
    printf 'x' > "${ROOT}/normal"
    run_wd
    cap | grep -q "\"scan_roots\":\"${ROOT}\""
}

@test "INVARIANT (sticky-bit dir): non-sticky world-writable DIRECTORY IS flagged" {
    # The script's find expression catches dirs with -type d -perm
    # -0002 ! -perm -1000 (world-writable but NOT sticky). A dir
    # with mode 0777 (no sticky bit) is flagged.
    mkdir "${ROOT}/non-sticky"; chmod 0777 "${ROOT}/non-sticky"
    run_wd
    cap | grep -q '"event":"world_writable_found"'
}

@test "INVARIANT (sticky-bit dir): sticky world-writable DIRECTORY is NOT flagged (the /tmp pattern)" {
    # Sticky bit (1000) on a 0777 dir → mode 1777 → /tmp pattern.
    # The script's `! -perm -1000` clause excludes it.
    mkdir "${ROOT}/sticky-scratch"; chmod 1777 "${ROOT}/sticky-scratch"
    run_wd
    cap | grep -q '"severity":"ok"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf 'x' > "${ROOT}/loose"; chmod 0666 "${ROOT}/loose"
    run_wd
    n=$(cap | grep -c '"tag":"selfdef-world-writable"')
    [ "${n}" = "1" ]
}

@test "report profile exits 0 even on alert severity (findings are advisory)" {
    for i in $(seq 1 30); do printf 'x' > "${ROOT}/ww${i}"; chmod 0666 "${ROOT}/ww${i}"; done
    PROFILE=report run run_wd
    [ "${status}" = "0" ]
    cap | grep -q '"severity":"alert"'
}
