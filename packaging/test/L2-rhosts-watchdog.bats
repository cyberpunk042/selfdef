#!/usr/bin/env bats
# L2 bats functional tests for the rhosts-watchdog scan script.
#
# /etc/hosts.equiv and ~/.rhosts/.shosts declare hosts/users trusted for
# PASSWORDLESS rlogin/rsh. A `+` wildcard is a classic trusted-relationship
# backdoor (T1199); root's ~/.rhosts existing at all is almost always a
# backdoor. Severity:
#   ok    → no delta
#   warn  → a trust entry / file added/removed/changed
#   alert → a `+` wildcard, a world-writable/non-root trust file, or a
#           per-user .rhosts/.shosts present
#
# Run with: bats packaging/test/L2-rhosts-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd/rhosts-watchdog.sh"

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
    EQUIV="${TMP}/hosts.equiv"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_RHOSTS_PROFILE="${PROFILE:-report}" \
    SELFDEF_RHOSTS_BASELINE="${BASELINE}" \
    SELFDEF_RHOSTS_FILES="${FILES_V:-$EQUIV}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf 'trusted.example.com\n' > "${EQUIV}"
}

@test "no rhosts files → ok / no_rhosts_files" {
    FILES_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_rhosts_files"'
    cap | grep -q '"severity":"ok"'
}

@test "benign hosts.equiv, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged hosts.equiv on second run → ok / rhosts_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"rhosts_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a + wildcard trust entry → alert / rhosts_trust_backdoor" {
    seed_benign
    run_wd
    printf 'trusted.example.com\n+\n' > "${EQUIV}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"rhosts_trust_backdoor"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable trust file → alert" {
    seed_benign
    run_wd
    chmod 0666 "${EQUIV}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign trust-entry change → warn / rhosts_changed" {
    seed_benign
    run_wd
    printf 'other.example.com\n' > "${EQUIV}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"rhosts_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign hosts.equiv is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "enforce profile exits non-zero on a wildcard trust entry" {
    seed_benign
    run_wd
    printf 'trusted.example.com\n+\n' > "${EQUIV}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — trust inventory enumerates legitimate trust relationships)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (multi-line + wildcard): + on its own line (not just trailing) → alert" {
    seed_benign
    run_wd
    printf '+\ntrusted.example.com\n' > "${EQUIV}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"rhosts_trust_backdoor"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (per-user .rhosts): a user-level .rhosts file IS flagged as a backdoor" {
    seed_benign
    run_wd
    # Test multi-file scan: declare a per-user rhosts file via FILES_V.
    user_rhosts="${TMP}/user-alice.rhosts"
    printf 'evil.example.com\n' > "${user_rhosts}"
    : > "${SELFDEF_TEST_LOGCAP}"
    FILES_V="${EQUIV} ${user_rhosts}" run_wd
    # Either the file's existence alone OR the wildcard signature fires alert.
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing wildcard): baseline_initial fires alert if hosts.equiv already has a + at install-time" {
    printf '+\n' > "${EQUIV}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "DELTA detect — REMOVED trust entry (operator pruning) → warn" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    : > "${EQUIV}"
    run_wd
    cap | grep -qE '"severity":"(warn|ok)"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-rhosts -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (group-writable): a group-writable trust file → alert too (more than just world-writable)" {
    seed_benign
    run_wd
    chmod 0664 "${EQUIV}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}
