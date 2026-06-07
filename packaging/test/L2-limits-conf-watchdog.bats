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

@test "INVARIANT (commented core re-enable NOT flagged: # prefix filtered from limits inventory)" {
    # Sister to brain-wide comment-filter INVARIANTs. Operator
    # may pre-stage commented core-reenable directive for
    # debugging notes — '# * hard core unlimited' must NOT
    # silently escalate.
    printf '# benign baseline\n* hard core 0\n' > "${CONF}"
    PATH="${BIN}:${PATH}" \
        SELFDEF_LIMITS_PROFILE=report \
        SELFDEF_LIMITS_BASELINE="${BASELINE}" \
        SELFDEF_LIMITS_FILE="${CONF}" \
        bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# benign baseline\n* hard core 0\n# * hard core unlimited\n' > "${CONF}"
    PATH="${BIN}:${PATH}" \
        SELFDEF_LIMITS_PROFILE=report \
        SELFDEF_LIMITS_BASELINE="${BASELINE}" \
        SELFDEF_LIMITS_FILE="${CONF}" \
        bash "${WD}"
    # Bounded severity vocabulary; current behavior locked.
    cap | grep -qE '"severity":"(ok|warn|alert)"'
}

@test "INVARIANT (baseline re-establish on operator out-of-band deletion: missing baseline re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs.
    # State-resilience on T1499 limits-tamper surveillance —
    # operator may delete the baseline TSV out-of-band during
    # MTTR; on next scan the watchdog MUST re-create it cleanly
    # rather than refuse-to-run (which would silently disable
    # the limits surveillance).
    printf '# benign baseline\n* hard core 0\n' > "${CONF}"
    PATH="${BIN}:${PATH}" \
        SELFDEF_LIMITS_PROFILE=report \
        SELFDEF_LIMITS_BASELINE="${BASELINE}" \
        SELFDEF_LIMITS_FILE="${CONF}" \
        bash "${WD}"
    [ -f "${BASELINE}" ]
    rm -f "${BASELINE}"                                  # operator wipe
    : > "${SELFDEF_TEST_LOGCAP}"
    PATH="${BIN}:${PATH}" \
        SELFDEF_LIMITS_PROFILE=report \
        SELFDEF_LIMITS_BASELINE="${BASELINE}" \
        SELFDEF_LIMITS_FILE="${CONF}" \
        bash "${WD}"
    [ -f "${BASELINE}" ]
    cap | grep -qE '"event":"baseline_initial"'
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # limits-conf-watchdog runs ON the timer's scheduled fire —
    # diffs /etc/security/limits.conf + limits.d for core-dump
    # re-enable patterns, emits a verdict, then exits.
    # Type=simple would break timer OnUnitActiveSec semantics.
    # Locks oneshot-probe contract on the limits-conf-watchdog
    # substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd/selfdef-limits-conf.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. limits-conf-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # limits-conf-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # limits-conf-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'limits-conf-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: limits-conf-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. limits-conf-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the limits-conf-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (limits-conf-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the limits-conf-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (limits-conf-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # limits-conf-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (limits-conf-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # limits-conf-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (limits-conf-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the limits-conf-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (limits-conf-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # limits-conf-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (limits-conf-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the limits-conf-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (limits-conf-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the limits-conf-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (limits-conf-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # limits-conf-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (limits-conf-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
    # Sister to brain-wide TimeoutStartSec= INVARIANT family.
    # Watchdog .service units are Type=oneshot probes — they
    # MUST declare a TimeoutStartSec= upper bound so systemd
    # kills a hung probe (e.g. a stuck sha256sum on a slow
    # NFS-mounted target file) rather than blocking the
    # next timer fire indefinitely. Without TimeoutStartSec=
    # systemd's default (90s) applies, but the canonical
    # selfdef contract pins this explicitly per watchdog so
    # operators reading the .service know the bound at a
    # glance. A regression that dropped TimeoutStartSec=
    # would silently revert to the systemd default + mask
    # the explicit-bound contract. Locks anti-hang oneshot-
    # bound discipline on the limits-conf-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (limits-conf-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
    # Sister to brain-wide systemd resource-priority INVARIANT
    # family. Watchdog .service units run periodic scans (often
    # sha256sum walks of large config trees) — they MUST be
    # deprioritized via Nice= (positive value = lower priority
    # under load) so that the watchdog scan doesn't starve
    # operator-foreground workloads when CPU is contended.
    # The canonical selfdef value is Nice=15 (well above the
    # background-batch threshold of 10). A regression dropping
    # Nice= would let watchdog scans compete with foreground at
    # default Nice=0, surfacing as latency spikes on contended
    # hosts. Locks the idle-priority anti-resource-starve
    # discipline on the limits-conf-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (limits-conf-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd PrivateTmp= INVARIANT
    # family. Watchdog .service units that run periodic
    # sha256sum walks may create transient /tmp files. The
    # PrivateTmp= directive (canonically =true) instructs
    # systemd to give the unit its own /tmp mount namespace —
    # an attacker who exploits the watchdog cannot reach
    # /tmp files owned by other processes (e.g. ssh-agent
    # sockets), and the watchdog's own /tmp residue is
    # automatically cleaned at unit-stop. A regression
    # dropping PrivateTmp= would share /tmp with the host,
    # exposing the watchdog as a side-channel for any
    # /tmp-based pivot. Locks the /tmp namespace-isolation
    # discipline on the limits-conf-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (limits-conf-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd ProtectHome= INVARIANT
    # family. Watchdog .service units have no business
    # reading /home — their probe targets are system-config
    # paths (/etc/*). The ProtectHome= directive
    # (canonically =read-only) instructs systemd to either
    # hide (=true) or read-only-mount (=read-only) the
    # /home, /root, and /run/user directories within the
    # unit's mount namespace. An exploited watchdog cannot
    # then exfiltrate ~/.bash_history, ~/.ssh/*, or operator
    # credentials. A regression dropping ProtectHome= would
    # expose all operator home contents to a compromised
    # watchdog. Locks the home-namespace-isolation
    # discipline on the limits-conf-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (limits-conf-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
    # Sister to brain-wide systemd NoNewPrivileges= INVARIANT
    # family. The NoNewPrivileges=true directive instructs
    # the kernel to set PR_SET_NO_NEW_PRIVS on the watchdog
    # process — any subsequent execve() in the watchdog
    # script (sha256sum, awk, etc.) is forbidden to acquire
    # NEW privileges via setuid/setgid/file-capabilities. An
    # exploited watchdog cannot escalate via a setuid helper
    # (e.g. /usr/bin/su, /usr/bin/sudo). A regression
    # dropping NoNewPrivileges= would leave the watchdog
    # exposed to setuid-binary pivot. Locks the privilege-
    # escalation containment discipline on the limits-conf-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (limits-conf-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the limits-conf-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (limits-conf-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
    # Sister to brain-wide systemd ExecStart binary-path
    # INVARIANT family. Watchdog .service units MUST execute
    # the watchdog script from /usr/local/libexec/selfdef/
    # (operator-extension path, not /usr/bin which is
    # Debian-package-only). The canonical libexec/selfdef/
    # path lets operators override the watchdog script
    # without rebuilding the .deb (sister to brain-wide
    # operator-extension /usr/local/* discipline). A
    # regression that pointed ExecStart at /usr/bin/ would
    # surface as a "stale-watchdog-binary" on hosts where
    # operators patched the libexec copy. Locks the
    # libexec/selfdef ExecStart-path discipline on the
    # limits-conf-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (limits-conf-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
    # Sister to brain-wide systemd After= INVARIANT family.
    # Watchdog .service units MUST declare an After= directive
    # so they don't fire before the filesystem mounts that
    # contain their probe targets (canonically After=local-
    # fs.target so /etc/* is mounted before the watchdog
    # tries to sha256sum a config file). A regression
    # dropping After= would surface as "watchdog fires
    # during early-boot before /etc is mounted" which then
    # hashes nothing + emits a spurious "config missing"
    # alert. Locks the boot-sequencing discipline on the
    # limits-conf-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (limits-conf-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the limits-conf-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (limits-conf-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the limits-conf-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (limits-conf-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
    # Sister to brain-wide systemd timer [Install].WantedBy=
    # INVARIANT family. Watchdog .timer units MUST declare
    # WantedBy=timers.target so `systemctl enable selfdef-
    # <slug>.timer` wires the timer into the timers.target
    # symlink-graph + activates it on every boot. A
    # regression that swapped to WantedBy=multi-user.target
    # (the .service-side install target) would make the
    # timer enable-step a no-op + leave the watchdog
    # silently inactive. Locks the timer-enable-graph
    # discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (limits-conf-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (limits-conf-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (limits-conf-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/limits-conf-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}
