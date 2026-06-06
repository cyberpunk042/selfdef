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

@test "baseline is chmod 0600 (confidentiality — hosts pinning inventory leaks operator internal hostnames)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (sensitive-domain: debian distro): security.debian.org pin → alert (block patching attack)" {
    seed_benign
    run_wd
    printf '127.0.0.1 localhost\n0.0.0.0 security.debian.org\n' > "${HOSTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (sensitive-domain: ubuntu distro): archive.ubuntu.com pin → alert" {
    seed_benign
    run_wd
    printf '127.0.0.1 localhost\n0.0.0.0 archive.ubuntu.com\n' > "${HOSTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (sensitive-domain: docker.io): docker registry pin → alert (image-pull MITM)" {
    seed_benign
    run_wd
    printf '127.0.0.1 localhost\n0.0.0.0 docker.io\n' > "${HOSTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (sensitive-domain: github.com): github pin → alert (source-pull MITM)" {
    seed_benign
    run_wd
    printf '127.0.0.1 localhost\n0.0.0.0 raw.githubusercontent.com\n' > "${HOSTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (pre-existing sensitive pin): baseline_initial fires alert if /etc/hosts already pins a sensitive domain at install-time" {
    # Install-time-vet contract.
    printf '0.0.0.0 security.debian.org\n' > "${HOSTS}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (persistent-alert on sensitive pin): pre-existing sensitive pin IS re-alerted on every run until removed" {
    # CONTRAST against the access-conf-watchdog + capability-conf-
    # watchdog "no spurious re-alert" contract. hosts-file-
    # watchdog scans the FULL current set for sensitive domains
    # (not just the added-set), so a sensitive pin that stays in
    # /etc/hosts STAYS in the alert state every run. This is
    # the "alert STAYS visible until operator removes" pattern,
    # implemented via re-evaluation rather than via no-baseline-
    # refresh. Locks the choice — a regression to scan only the
    # added-set (matching access-conf semantics) would let an
    # attacker-pinned sensitive domain go silent after the first
    # alert.
    printf '0.0.0.0 security.debian.org\n' > "${HOSTS}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"hosts_file_sensitive_pin"'
    cap | grep -q '"severity":"alert"'
}

@test "DELTA detect — REMOVED hosts entry → warn / hosts_file_changed" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '127.0.0.1 localhost\n' > "${HOSTS}"        # remove myserver
    run_wd
    cap | grep -qE '"event":"hosts_file_changed"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-hosts-file -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (auto-trust): hosts-file-watchdog DOES auto-refresh the baseline (operator-action common)" {
    seed_benign
    run_wd
    printf '127.0.0.1 localhost\n10.0.0.10 newserver.internal\n' > "${HOSTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — warn
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # baseline refreshed
    cap | grep -q '"event":"hosts_file_intact"'
}

@test "INVARIANT (commented sensitive pin NOT flagged: # prefix filtered from inventory)" {
    # /etc/hosts uses # comments. Operator notes about hypothetical
    # bad pins must NOT trigger alert.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '127.0.0.1 localhost\n10.0.0.5 myserver.internal\n# 0.0.0.0 security.debian.org\n' > "${HOSTS}"
    run_wd
    ! cap | grep -q '"event":"hosts_file_sensitive_pin"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (sensitive-domain: PyPI / pypi.org pin → alert (python supply-chain MITM))" {
    seed_benign
    run_wd
    printf '127.0.0.1 localhost\n0.0.0.0 pypi.org\n' > "${HOSTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (sensitive-domain: npmjs.org / npm registry pin → alert (node supply-chain MITM))" {
    seed_benign
    run_wd
    printf '127.0.0.1 localhost\n0.0.0.0 registry.npmjs.org\n' > "${HOSTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (whitespace tolerance: '0.0.0.0    security.debian.org' multi-space variant still triggers alert)" {
    # Attacker may use multi-spaces to evade naive grep-based
    # detection. Lock whitespace-tolerant parser.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '127.0.0.1 localhost\n0.0.0.0    security.debian.org\n' > "${HOSTS}"
    run_wd
    cap | grep -q '"severity":"alert"'
}
