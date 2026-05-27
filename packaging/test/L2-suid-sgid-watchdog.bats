#!/usr/bin/env bats
# L2 bats functional tests for the suid-sgid-watchdog scan script.
#
# A daily inventory + baseline delta of every setuid/setgid executable. A
# newly-planted setuid-root binary is a classic privilege-escalation
# persistence primitive (T1548.001). Severity is count-based on the delta:
#   ok    → no delta
#   warn  → 1..3 added or perm-changed, OR any hash-changed
#   alert → 4+ added or perm-changed (bulk-install attack)
#
# Runs the actual scan script with `logger` shadowed on PATH and a tmp
# scan-root + baseline via SELFDEF_SUIDSGID_ROOTS / _BASELINE. (Tests create
# real setuid files, so they must run as a user able to chmod u+s — true in
# the CI/root sandbox.)
#
# Run with: bats packaging/test/L2-suid-sgid-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd/suid-sgid-watchdog.sh"

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
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_SUIDSGID_PROFILE="${PROFILE:-report}" \
    SELFDEF_SUIDSGID_ROOTS="${ROOT}" \
    SELFDEF_SUIDSGID_BASELINE="${BASELINE}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

mk_suid() { printf 'ELF-%s' "$1" > "${ROOT}/$1"; chmod 4755 "${ROOT}/$1"; }

@test "first run with one suid binary → ok / baseline_initial" {
    mk_suid sudo
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged inventory on second run → ok / no_delta" {
    mk_suid sudo
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
}

@test "one added suid binary → warn / suid_drift" {
    mk_suid sudo
    run_wd
    mk_suid newsuid
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"suid_drift"'
    cap | grep -q '"severity":"warn"'
}

@test "four added suid binaries → alert / bulk_delta" {
    mk_suid sudo
    run_wd
    mk_suid a1; mk_suid a2; mk_suid a3; mk_suid a4
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"bulk_delta"'
    cap | grep -q '"severity":"alert"'
}

@test "content change of an existing suid binary → warn / suid_hash_drift" {
    mk_suid sudo
    run_wd
    printf 'ELF-tampered' > "${ROOT}/sudo"   # same path/mode/owner, new hash
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"suid_hash_drift"'
    cap | grep -q '"severity":"warn"'
}

@test "enforce profile exits non-zero on an added suid binary" {
    mk_suid sudo
    run_wd
    mk_suid newsuid
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
}
