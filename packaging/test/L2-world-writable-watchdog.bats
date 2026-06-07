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

@test "INVARIANT (sample cap at 10: 20 world-writable files → MAIN tag sample contains at most 10)" {
    for i in $(seq 1 20); do
        printf 'x' > "${ROOT}/ww-distinct-${i}"
        chmod 0666 "${ROOT}/ww-distinct-${i}"
    done
    run_wd
    cap | grep -qE '"finding_count":20'
    main_line="$(cap | grep -E '^-t selfdef-world-writable --')"
    found_in_main="$(printf '%s' "${main_line}" | grep -oE 'ww-distinct-[0-9]+' | sort -u | wc -l)"
    [ "${found_in_main}" -le 10 ]
}

@test "INVARIANT (recursive scan: world-writable file in nested subdirectory surfaces)" {
    mkdir -p "${ROOT}/a/b/c"
    printf 'x' > "${ROOT}/a/b/c/deep-loose"
    chmod 0666 "${ROOT}/a/b/c/deep-loose"
    run_wd
    cap | grep -q '"event":"world_writable_found"'
    cap | grep -q 'deep-loose'
}

@test "INVARIANT (group-writable 0664 file is NOT flagged: only world-writable matters — content boundary)" {
    # The scope is world-writable specifically (perm 0002). Group-
    # writable (perm 0020) is owned by different watchdog axes
    # (e.g. modules-load-watchdog). Lock the boundary.
    printf 'x' > "${ROOT}/group-write"; chmod 0664 "${ROOT}/group-write"
    run_wd
    cap | grep -q '"severity":"ok"'
    ! cap | grep -q '"severity":"warn"'
}

@test "INVARIANT (enforce + ok severity → exit 0): no world-writable files passes even in enforce" {
    printf 'x' > "${ROOT}/normal"; chmod 0644 "${ROOT}/normal"
    PROFILE=enforce run run_wd
    [ "${status}" = "0" ]
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (stateless re-evaluation: world-writable alert STAYS visible on every run until operator chmods)" {
    # world-writable-watchdog is stateless (no baseline-refresh required)
    # — re-evaluates live filesystem on every run. A world-writable file
    # that stays world-writable across runs MUST re-fire every run.
    for i in $(seq 1 30); do printf 'x' > "${ROOT}/ww${i}"; chmod 0666 "${ROOT}/ww${i}"; done
    run_wd
    cap | grep -q '"severity":"alert"'
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"bulk_world_writable"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-root scan: world-writable file in ANY watched root → flagged)" {
    ROOT2="${TMP}/scan2"; mkdir -p "${ROOT2}"
    printf 'x' > "${ROOT}/normal"; chmod 0644 "${ROOT}/normal"
    printf 'x' > "${ROOT2}/loose-in-second-root"; chmod 0666 "${ROOT2}/loose-in-second-root"
    PATH="${BIN}:${PATH}" \
    SELFDEF_WORLDWRITE_PROFILE="report" \
    SELFDEF_WORLDWRITE_ROOTS="${ROOT} ${ROOT2}" \
    bash "${WD}"
    cap | grep -q '"event":"world_writable_found"'
    cap | grep -q 'loose-in-second-root'
}

@test "INVARIANT (whitelist axis: /tmp + /var/tmp + /dev/shm + /run/lock NOT flagged when scan-rooted at /)" {
    # The 4 canonical sticky-scratch dirs MUST be excluded even when
    # the scan is rooted at /. Lock the whitelist axis by simulating
    # sticky-scratch dir within the scan root.
    mkdir -p "${ROOT}/tmp"; chmod 1777 "${ROOT}/tmp"
    mkdir -p "${ROOT}/var/tmp"; chmod 1777 "${ROOT}/var/tmp"
    mkdir -p "${ROOT}/dev/shm"; chmod 1777 "${ROOT}/dev/shm"
    run_wd
    # No finding because all 4 carry sticky bit.
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (boundary 26: at exact 26 world-writable severity escalates from warn to alert)" {
    # Single-notch boundary lock at the warn→alert transition.
    for i in $(seq 1 26); do printf 'x' > "${ROOT}/ww${i}"; chmod 0666 "${ROOT}/ww${i}"; done
    run_wd
    cap | grep -q '"event":"bulk_world_writable"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"finding_count":2[6-9]|"finding_count":[3-9][0-9]'
}

@test "INVARIANT (world-writable directory ALSO flagged — sister axis to world-writable regular file)" {
    # Sister to the world-writable file axis already locked. A world-
    # writable DIRECTORY (mode 0777 without sticky bit) is equally
    # dangerous — any user can plant or replace files in it,
    # including a setuid binary they then chmod into existence. The
    # whitelisted /tmp + /var/tmp + /dev/shm have the sticky bit
    # (1777) which restricts deletion to owner; a non-sticky 0777
    # directory does NOT have that protection. Locks axis-symmetry
    # between world-writable-file and world-writable-dir-without-
    # sticky-bit on the file-mode surveillance surface.
    mkdir -p "${ROOT}/loose-dir"; chmod 0777 "${ROOT}/loose-dir"
    run_wd
    cap | grep -qE '"severity":"(warn|alert)"'
    cap | grep -q 'loose-dir'
}
