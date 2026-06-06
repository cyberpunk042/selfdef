#!/usr/bin/env bats
# L2 functional suite for logfile-integrity-watchdog.
#
# logfile-integrity-watchdog detects log tampering via monotonic-
# growth + inode-stability tracking. Append-only logs only ever
# GROW until logrotate rotates them (which changes the inode and
# resets size — a KNOWN benign signature). An attacker erasing
# their tracks truncates / rewrites the log in place → size SHRINKS
# with the SAME inode. That combination (same inode, smaller size)
# has no benign cause and is THE indicator-removal signature.
#
# Severity tiers:
#   ok    → all logs grew or rotated cleanly (new inode)
#   warn  → a log went missing (deleted)
#   alert → same-inode size shrink (in-place truncation — tamper
#           signature)
#
# Uses SELFDEF_LOGINT_WATCH env-var (added 2026-06-06, colon-
# separated PATH-style watch list) so the L2 suite controls the
# exact set of files tracked. Live default behavior unchanged.
#
# Run with: bats packaging/test/L2-logfile-integrity-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd/logfile-integrity-watchdog.sh"

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
    STATE="${TMP}/logfile-integrity-state.tsv"
    LOG1="${TMP}/log1.log"
    LOG2="${TMP}/log2.log"
    WATCH="${LOG1}:${LOG2}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_LOGINT_PROFILE="${PROFILE:-report}" \
    SELFDEF_LOGINT_STATE="${STATE}" \
    SELFDEF_LOGINT_WATCH="${WATCH}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "first run captures state + chmod 0600" {
    printf 'line 1\nline 2\n' > "${LOG1}"
    printf 'one entry\n' > "${LOG2}"
    run_wd
    [ -f "${STATE}" ]
    [ "$(stat -c '%a' "${STATE}")" = "600" ]
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"tracked":2'
}

@test "logs grew normally (append-only) → ok / logs_intact" {
    printf 'line 1\nline 2\n' > "${LOG1}"
    printf 'one\n' > "${LOG2}"
    run_wd
    # Append to both logs.
    printf 'line 3\n' >> "${LOG1}"
    printf 'two\nthree\n' >> "${LOG2}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"logs_intact"'
    cap | grep -q '"severity":"ok"'
    cap | grep -qE '"grew":2'
    cap | grep -qE '"shrinks":0'
}

@test "log truncated in place (same inode, smaller size) → alert / log_truncation_detected (the tamper signature)" {
    printf 'line 1\nline 2\nline 3\nline 4\n' > "${LOG1}"
    run_wd
    # In-place truncation via shell `>` redirect KEEPS the inode but
    # zeroes the size — the attack signature.
    : > "${LOG1}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"log_truncation_detected"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"shrinks":1'
}

@test "partial in-place truncation (size shrinks but >0) → alert" {
    printf 'aaaaaaaaaaaaaaa\nbbbbbbbbbbbb\nccccccccc\n' > "${LOG1}"
    run_wd
    # Truncate to a smaller size, KEEP the same inode (write-in-place).
    printf 'aa\n' > "${LOG1}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"log_truncation_detected"'
    cap | grep -q '"severity":"alert"'
}

@test "log ROTATED (new inode, smaller size) → ok / logs_intact (benign logrotate signature)" {
    printf 'line 1\nline 2\nline 3\n' > "${LOG1}"
    run_wd
    # Simulate logrotate: rename + create new file (NEW INODE, smaller).
    mv "${LOG1}" "${LOG1}.1"
    printf 'header\n' > "${LOG1}"          # new inode, smaller size
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    # Inode mismatch → counted as "rotated", NOT "shrinks". Severity ok.
    cap | grep -q '"event":"logs_intact"'
    cap | grep -q '"severity":"ok"'
    cap | grep -qE '"shrinks":0'
    cap | grep -qE '"rotated":1'
}

@test "log MISSING (deleted) → warn / log_missing" {
    printf 'line 1\n' > "${LOG1}"
    printf 'one\n' > "${LOG2}"
    run_wd
    rm -f "${LOG1}"     # log deleted entirely
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"log_missing"'
    cap | grep -q '"severity":"warn"'
    cap | grep -qE '"missing":1'
}

@test "shrink takes precedence over missing (alert wins over warn)" {
    printf 'line 1\nline 2\nline 3\n' > "${LOG1}"
    printf 'one\n' > "${LOG2}"
    run_wd
    : > "${LOG1}"        # in-place truncation → alert
    rm -f "${LOG2}"      # delete  → warn (would be warn if alone)
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    # alert wins
    cap | grep -q '"event":"log_truncation_detected"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"shrinks":1'
    cap | grep -qE '"missing":1'
}

@test "the emitted JSON carries every promised schema field" {
    printf 'aa\n' > "${LOG1}"
    run_wd
    line="$(cap)"
    printf '%s' "${line}" | grep -q '"tag":"selfdef-logfile-integrity"'
    printf '%s' "${line}" | grep -q '"severity":'
    printf '%s' "${line}" | grep -q '"event":'
    printf '%s' "${line}" | grep -q '"profile":'
    printf '%s' "${line}" | grep -qE '"tracked":[0-9]+'
}

@test "shrink sample carries 'SHRANK:<path>:<old>-><new>' format" {
    printf 'aaaaaaaaaaaaaaaaaa\nbbbbbbb\n' > "${LOG1}"
    run_wd
    : > "${LOG1}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    # SHRANK label + path + old/new size pair.
    cap | grep -q "SHRANK:${LOG1}"
}

@test "enforce profile + log truncated → exit 1" {
    printf 'aaaaaaaa\n' > "${LOG1}"
    run_wd
    : > "${LOG1}"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_LOGINT_PROFILE=enforce \
        SELFDEF_LOGINT_STATE="${STATE}" \
        SELFDEF_LOGINT_WATCH="${WATCH}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
}

@test "enforce profile + unchanged → exit 0" {
    printf 'aa\n' > "${LOG1}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run_wd
    cap | grep -q '"severity":"ok"'
}
