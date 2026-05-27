#!/usr/bin/env bats
# L2 bats functional tests for the hosts-file-watchdog scan script.
#
# /etc/hosts is consulted before DNS; an attacker who pins or blackholes a
# sensitive package/security/CA domain can MITM updates, block patching, or
# redirect the supply chain (T1565.001 / T1562.001). Severity:
#   ok    → no delta
#   warn  → any entry added/removed/changed
#   alert → an entry maps a sensitive package/security/CA domain (any IP)
#
# Run with: bats packaging/test/L2-hosts-file-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/hosts-file-watchdog/systemd/hosts-file-watchdog.sh"

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
    HOSTS="${TMP}/hosts"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_HOSTS_PROFILE="${PROFILE:-report}" \
    SELFDEF_HOSTS_BASELINE="${BASELINE}" \
    SELFDEF_HOSTS_FILE="${HOSTS_V:-$HOSTS}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '127.0.0.1 localhost\n10.0.0.5 myserver.internal\n' > "${HOSTS}"
}

@test "no hosts file → ok / no_hosts_file" {
    HOSTS_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_hosts_file"'
    cap | grep -q '"severity":"ok"'
}

@test "benign hosts file, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged hosts file on second run → ok / hosts_file_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"hosts_file_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "pinning a sensitive package domain → alert / hosts_file_sensitive_pin" {
    seed_benign
    run_wd
    printf '127.0.0.1 localhost\n10.0.0.5 myserver.internal\n185.1.2.3 security.ubuntu.com\n' > "${HOSTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"hosts_file_sensitive_pin"'
    cap | grep -q '"severity":"alert"'
}

@test "a benign entry change → warn / hosts_file_changed" {
    seed_benign
    run_wd
    printf '127.0.0.1 localhost\n10.0.0.6 other.internal\n' > "${HOSTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"hosts_file_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign internal-only hosts file is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "enforce profile exits non-zero on a sensitive pin" {
    seed_benign
    run_wd
    printf '127.0.0.1 localhost\n0.0.0.0 security.debian.org\n' > "${HOSTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
