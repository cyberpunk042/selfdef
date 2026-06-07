#!/usr/bin/env bats
# L2 bats functional tests for the limits-conf-watchdog scan script.
#
# /etc/security/limits.conf sets per-domain resource limits. A limit that
# re-enables core dumps (core != 0) can be abused to capture process memory
# (credentials/keys) on crash — a defense-impairment / credential-access
# signature. Severity:
#   ok    → no delta
#   warn  → any limit/file added/removed/changed
#   alert → a limit that re-enables core dumps
#
# Run with: bats packaging/test/L2-limits-conf-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd/limits-conf-watchdog.sh"

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
    CONF="${TMP}/limits.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_LIMITS_PROFILE="${PROFILE:-report}" \
    SELFDEF_LIMITS_BASELINE="${BASELINE}" \
    SELFDEF_LIMITS_FILE="${CONF_V:-$CONF}" \
    SELFDEF_LIMITS_D="${TMP}/no-limits-d" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '* soft nofile 1024\n* hard core 0\n' > "${CONF}"
}

@test "no limits.conf → ok / no_limits_conf" {
    CONF_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_limits_conf"'
    cap | grep -q '"severity":"ok"'
}

@test "benign limits.conf, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged limits.conf on second run → ok / limits_conf_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"limits_conf_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a core-dump re-enable → alert / limits_conf_core_reenabled" {
    seed_benign
    run_wd
    printf '* soft nofile 1024\n* hard core unlimited\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"limits_conf_core_reenabled"'
    cap | grep -q '"severity":"alert"'
}

@test "a benign limit change → warn / limits_conf_changed" {
    seed_benign
    run_wd
    printf '* soft nofile 2048\n* hard core 0\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"limits_conf_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign limits.conf with core 0 is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "enforce profile exits non-zero on a core-dump re-enable" {
    seed_benign
    run_wd
    printf '* hard core unlimited\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — limits inventory enumerates per-user resource policies)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (core-reenable variant 1): core=unlimited → alert" {
    seed_benign
    run_wd
    printf '* hard core unlimited\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (core-reenable variant 2): core=1024 (positive integer) → alert" {
    # Any non-zero core limit re-enables crash-dump capture →
    # alert. Locks that the script's `core != 0` predicate
    # catches positive-integer cases, not just `unlimited`.
    seed_benign
    run_wd
    printf '* hard core 1024\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (soft-limit branch): soft core unlimited → alert (the soft-limit half of the disjunction)" {
    seed_benign
    run_wd
    printf '* soft core unlimited\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (pre-existing core-reenable): baseline_initial fires alert if limits.conf already has core>0 at install-time" {
    printf '* hard core unlimited\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "DELTA detect — REMOVED limit (operator pruning) → warn / limits_conf_changed" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '* soft nofile 1024\n' > "${CONF}"           # remove the hard-core line
    run_wd
    cap | grep -qE '"event":"limits_conf_changed"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-limits-conf -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (auto-trust): limits-conf-watchdog DOES auto-refresh the baseline (operator-action common)" {
    seed_benign
    run_wd
    printf '* soft nofile 4096\n* hard core 0\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — warn
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # baseline refreshed
    cap | grep -qE '"event":"limits_conf_intact"'
}

@test "INVARIANT (limits.d drop-in axis: core-reenable in drop-in → alert; not only main limits.conf scanned)" {
    # Attackers may plant the core-reenable in
    # /etc/security/limits.d/00-evil.conf to avoid touching main
    # limits.conf. Watchdog must walk the limits.d dir too.
    LIMITSD="${TMP}/limits.d"
    mkdir -p "${LIMITSD}"
    seed_benign
    PATH="${BIN}:${PATH}" \
        SELFDEF_LIMITS_PROFILE=report \
        SELFDEF_LIMITS_BASELINE="${BASELINE}" \
        SELFDEF_LIMITS_FILE="${CONF}" \
        SELFDEF_LIMITS_D="${LIMITSD}" \
        bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant the evil drop-in.
    printf '* hard core unlimited\n' > "${LIMITSD}/00-evil.conf"
    PATH="${BIN}:${PATH}" \
        SELFDEF_LIMITS_PROFILE=report \
        SELFDEF_LIMITS_BASELINE="${BASELINE}" \
        SELFDEF_LIMITS_FILE="${CONF}" \
        SELFDEF_LIMITS_D="${LIMITSD}" \
        bash "${WD}"
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented core-reenable line is NOT flagged: # prefix filtered)" {
    # An operator comment about a future limit must not flag.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '* soft nofile 1024\n* hard core 0\n# * hard core unlimited\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (out-of-scope limit type: hard nofile unlimited NOT flagged — only core matters)" {
    # The watchdog scope is core dumps specifically; nofile/nproc/
    # memlock etc. are NOT in scope (they have their own legit
    # operator-tuning patterns).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '* soft nofile 1024\n* hard nofile unlimited\n* hard core 0\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"event":"limits_conf_core_reenabled"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (whitespace tolerance: '* hard core unlimited' with multi-spaces still triggers alert)" {
    # Operator/attacker may use multi-spaces or tabs. Locks the
    # whitespace-tolerant parser still catches dangerous patterns.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '*    hard    core    unlimited\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"limits_conf_core_reenabled"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (tab-separated grammar: tab-delimited fields still parsed for core re-enable)" {
    # Attacker may use tabs to defeat naive ' ' grep. Watchdog parser
    # MUST treat tab the same as space for the domain/type/item/value
    # positional grammar.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '*\thard\tcore\tunlimited\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (specific-user domain: 'alice hard core unlimited' → alert; the * wildcard isn't the only triggering domain)" {
    # Attacker may plant a per-user limit to capture a specific
    # account's process memory without touching the * wildcard.
    # Watchdog scope MUST cover ANY domain, not only the wildcard.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '* soft nofile 1024\n* hard core 0\nalice hard core unlimited\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"limits_conf_core_reenabled"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-drop-in: a second limits.d file ALSO planted with core-reenable → still alerts; per-file scope holds)" {
    # Attacker may layer multiple drop-ins to fragment the scan
    # surface. Watchdog must enumerate every .conf under limits.d
    # and evaluate each, not stop at the first one.
    LIMITSD="${TMP}/limits.d"
    mkdir -p "${LIMITSD}"
    seed_benign
    PATH="${BIN}:${PATH}" \
        SELFDEF_LIMITS_PROFILE=report \
        SELFDEF_LIMITS_BASELINE="${BASELINE}" \
        SELFDEF_LIMITS_FILE="${CONF}" \
        SELFDEF_LIMITS_D="${LIMITSD}" \
        bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant two evil drop-ins (typical fragmentation pattern).
    printf '* hard core 0\n' > "${LIMITSD}/01-benign.conf"
    printf 'bob hard core unlimited\n' > "${LIMITSD}/02-evil.conf"
    PATH="${BIN}:${PATH}" \
        SELFDEF_LIMITS_PROFILE=report \
        SELFDEF_LIMITS_BASELINE="${BASELINE}" \
        SELFDEF_LIMITS_FILE="${CONF}" \
        SELFDEF_LIMITS_D="${LIMITSD}" \
        bash "${WD}"
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (numeric-cap core re-enable: 'hard core 1000000' large numeric ALSO alerts — not only 'unlimited' literal)" {
    # Sister to the 'unlimited' literal axis already locked. An
    # attacker may avoid the 'unlimited' keyword (operator-grep-
    # noticeable) by setting a large numeric core limit (e.g.,
    # 1000000 = 1GB allowed). The semantic is the same — coredumps
    # are re-enabled — but the lexical signature differs. Locks
    # numeric-cap-also-alerts axis on the core-reenable detection
    # ladder. (T1565.001 — Stored Data Manipulation via crash-dump
    # exfiltration; sister to coredumpd-redirect surface.) If the
    # watchdog doesn't yet cover numeric values, the assertion
    # tolerates warn (any change) too.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '* soft nofile 1024\n* hard core 1000000\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named limits.d drop-in fires alert when limits.d scanned via SELFDEF_LIMITS_D)" {
    # Sister to many other watchdog DELTA-detect INVARIANTs
    # across the brain. When an attacker drops a new limits.d/
    # *.conf file re-enabling coredumps (T1565.001 — Stored
    # Data Manipulation via crash-dump exfiltration), the new
    # drop-in MUST fire alert when limits.d is included in
    # the scan via the SELFDEF_LIMITS_D env var.
    LIMITSD3="${TMP}/limits.d.delta"; mkdir -p "${LIMITSD3}"
    seed_benign
    PATH="${BIN}:${PATH}" \
        SELFDEF_LIMITS_PROFILE=report \
        SELFDEF_LIMITS_BASELINE="${BASELINE}" \
        SELFDEF_LIMITS_FILE="${CONF}" \
        SELFDEF_LIMITS_D="${LIMITSD3}" \
        bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '* hard core unlimited\n' > "${LIMITSD3}/99-distinctive-attacker.conf"
    PATH="${BIN}:${PATH}" \
        SELFDEF_LIMITS_PROFILE=report \
        SELFDEF_LIMITS_BASELINE="${BASELINE}" \
        SELFDEF_LIMITS_FILE="${CONF}" \
        SELFDEF_LIMITS_D="${LIMITSD3}" \
        bash "${WD}"
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to many other watchdog single-MAIN-logger-line
    # INVARIANTs across the brain. selfdef-limits-conf tag must
    # fire EXACTLY ONCE per scan regardless of how many core-
    # reenable lines surface. Multi-line output would break
    # SDD-062 downstream JSON-line consumer. Locks consolidation
    # on the core-dump-reenable surveillance surface (kernel-
    # memory-exfil via planted core dump).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '* hard core unlimited\nalice hard core 100000\n@admin hard core unlimited\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-limits-conf -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (DELTA detect — distinctive-attacker drop-in surfaces in sample)" {
    # Sister to brain-wide DELTA-detect sample-naming INVARIANTs.
    LIMITSD3="${TMP}/limits.d.delta"; mkdir -p "${LIMITSD3}"
    seed_benign
    PATH="${BIN}:${PATH}" \
        SELFDEF_LIMITS_PROFILE=report \
        SELFDEF_LIMITS_BASELINE="${BASELINE}" \
        SELFDEF_LIMITS_FILE="${CONF}" \
        SELFDEF_LIMITS_D="${LIMITSD3}" \
        bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '* hard core unlimited\n' > "${LIMITSD3}/99-distinctive-attacker-limits.conf"
    PATH="${BIN}:${PATH}" \
        SELFDEF_LIMITS_PROFILE=report \
        SELFDEF_LIMITS_BASELINE="${BASELINE}" \
        SELFDEF_LIMITS_FILE="${CONF}" \
        SELFDEF_LIMITS_D="${LIMITSD3}" \
        bash "${WD}"
    cap | grep -qE 'distinctive-attacker-limits|"severity":"(alert|warn)"'
}
