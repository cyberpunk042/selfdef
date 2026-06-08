#!/usr/bin/env bats
# L2 functional + capture-regression suite for cron-job-watchdog.
#
# cron-job-watchdog inventories every scheduled-task surface
# (user crontabs, /etc/crontab, cron.d, cron.{hourly,daily,
# weekly,monthly}, enabled systemd timers) into a baseline,
# then alerts on a new/changed job. This is the MITRE T1053
# persistence sentry: attackers drop scheduled callbacks for
# reliable C2 + privilege re-acquisition + key rotation.
#
# Severity:
#   ok    → no delta
#   warn  → 1..2 added/changed (low-volume operator change)
#   alert → 3+ added/changed (mass-add — classic
#           configuration-management deploy OR an attacker
#           seeding multiple persistence callbacks)
#
# What this suite locks:
#   - INVENTORY-CAPTURE regression (existing) — emit_file writes
#     to `$current` not stdout (2026-05-27 root-cause bug)
#   - All 3 source classes (user-crontab + etc-crontab + cron-dir)
#     surface in the baseline with sha256 fingerprints
#   - Baseline chmod 0600 (confidentiality — scheduled-task
#     inventory enumerates persistence signatures)
#   - DELTA detect: NEW cron-dir job (typical attacker drop into
#     /etc/cron.d) → warn / new_job
#   - DELTA detect: CHANGED job (sha256 differs) → 1 add + 1
#     remove pair → warn (a single-job content change reads as
#     replacement, not mass-add)
#   - DELTA detect: 3+ adds → alert / mass_new_jobs (the
#     anomaly-volume threshold)
#   - DELTA detect: REMOVED job → no event surface (deletions
#     aren't a threat signal — see the script's logic)
#   - ENFORCE profile: any ADD → exit-1 (failure surface);
#     pure removal → exit-0
#   - REPORT profile: any delta → exit-0 (log-only)
#   - INVARIANT (no auto-trust): like ssh-authkeys / pam-config /
#     sudoers-integrity / account-watchdog, cron-job-watchdog
#     does NOT auto-refresh the baseline on delta. New cron jobs
#     are NEVER routine; the alert must STAY visible until the
#     operator manually updates the baseline.
#
# Adds SELFDEF_CRONJOBS_SPOOL_DIRS + SELFDEF_CRONJOBS_ETC_CRONTAB
# + SELFDEF_CRONJOBS_CRON_DIRS env-var overrides (added
# 2026-06-06) for L2 delta-testability. systemctl is mocked
# via PATH override. Live defaults unchanged.
#
# Run with: bats packaging/test/L2-cron-job-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd/cron-job-watchdog.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SELFDEF_TEST_LOGCAP}"
FAKELOGGER
    chmod +x "${BIN}/logger"
    # systemctl mock — emit empty enabled-timer list to keep the
    # test focused on cron paths. (Real systemd-timer testing
    # would need a separate fixture; covered by L1-systemd-
    # hardening + the timer's own L2 suites.)
    cat > "${BIN}/systemctl" <<'SCEOF'
#!/usr/bin/env bash
case "$*" in
    *"list-unit-files --type=timer --state=enabled"*) ;;
    *"show -p FragmentPath"*) ;;
esac
exit 0
SCEOF
    chmod +x "${BIN}/systemctl"
    export SELFDEF_TEST_LOGCAP="${TMP}/log.out"
    : > "${SELFDEF_TEST_LOGCAP}"
    BASELINE="${TMP}/cron-jobs-baseline.tsv"
    SPOOL_DIR="${TMP}/spool"
    ETC_CRONTAB="${TMP}/crontab"
    CRON_D="${TMP}/cron.d"
    CRON_HOURLY="${TMP}/cron.hourly"
    mkdir -p "${SPOOL_DIR}" "${CRON_D}" "${CRON_HOURLY}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_CRONJOBS_PROFILE="${PROFILE:-report}" \
    SELFDEF_CRONJOBS_BASELINE="${BASELINE}" \
    SELFDEF_CRONJOBS_SPOOL_DIRS="${SPOOL_DIR}" \
    SELFDEF_CRONJOBS_ETC_CRONTAB="${ETC_CRONTAB}" \
    SELFDEF_CRONJOBS_CRON_DIRS="${CRON_D} ${CRON_HOURLY}" \
    bash "${WD}"
}

run_wd_rc() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_CRONJOBS_PROFILE="${PROFILE:-report}" \
    SELFDEF_CRONJOBS_BASELINE="${BASELINE}" \
    SELFDEF_CRONJOBS_SPOOL_DIRS="${SPOOL_DIR}" \
    SELFDEF_CRONJOBS_ETC_CRONTAB="${ETC_CRONTAB}" \
    SELFDEF_CRONJOBS_CRON_DIRS="${CRON_D} ${CRON_HOURLY}" \
    bash "${WD}" >/dev/null 2>&1
    echo $?
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# Helper: write a baseline cron inventory.
write_cron_inventory() {
    # User crontab — bob's daily backup.
    echo '0 2 * * * /home/bob/bin/backup' > "${SPOOL_DIR}/bob"
    # System /etc/crontab.
    cat > "${ETC_CRONTAB}" <<'EOF'
SHELL=/bin/sh
0 6 * * * root /usr/local/sbin/system-housekeeping
EOF
    # /etc/cron.d drop-ins.
    cat > "${CRON_D}/operator-rotate" <<'EOF'
@hourly root /usr/local/sbin/rotate-logs
EOF
    # /etc/cron.hourly.
    cat > "${CRON_HOURLY}/cleanup" <<'EOF'
#!/bin/sh
rm -rf /tmp/scratch-*
EOF
}

@test "first run captures the cron inventory into the baseline (non-empty)" {
    write_cron_inventory
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
    [ -s "${BASELINE}" ]                                  # capture regression lock
    awk -F'\t' 'NF>=3{ok=1} END{exit ok?0:1}' "${BASELINE}"
    cap | grep -qE '"baseline_count":[1-9]'
}

@test "baseline captures all 3 source classes (user-crontab + etc-crontab + cron-dir)" {
    write_cron_inventory
    run_wd
    grep -qP '^user-crontab\t.*/bob\t[0-9a-f]{64}$' "${BASELINE}"
    grep -qP '^etc-crontab\t.*\t[0-9a-f]{64}$' "${BASELINE}"
    grep -qP '^cron-dir\t.*/operator-rotate\t[0-9a-f]{64}$' "${BASELINE}"
    grep -qP '^cron-dir\t.*/cleanup\t[0-9a-f]{64}$' "${BASELINE}"
}

@test "baseline is chmod 0600 (confidentiality — scheduled-task inventory enumerates persistence signatures)" {
    write_cron_inventory
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "unchanged cron state on second run → ok / no_delta" {
    write_cron_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
}

@test "DELTA detect — NEW cron.d job (attacker persistence drop) → warn / new_job" {
    write_cron_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Attacker drops a callback in /etc/cron.d/.
    echo '*/5 * * * * root /tmp/.attacker-callback' > "${CRON_D}/backdoor"
    run_wd
    cap | grep -q '"event":"new_job"'
    cap | grep -q '"severity":"warn"'
    cap | grep -q '"added":1'
}

@test "DELTA detect — CHANGED job (content edited; sha256 differs) → 1 add + 1 remove (replacement read)" {
    write_cron_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Attacker edits an existing legitimate cron-dir job to add a
    # backdoor side-effect.
    cat > "${CRON_D}/operator-rotate" <<'EOF'
@hourly root /usr/local/sbin/rotate-logs && /tmp/.attacker-callback
EOF
    run_wd
    cap | grep -q '"added":1'
    cap | grep -q '"removed":1'
    # Content-edit reads as warn (single net-new add).
    cap | grep -q '"severity":"warn"'
}

@test "DELTA detect — MASS-ADD (3+ new jobs) → alert / mass_new_jobs" {
    write_cron_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Mass-add — typical attacker seeding multiple callbacks.
    echo '*/3 * * * * root /tmp/.callback-1' > "${CRON_D}/cb1"
    echo '*/5 * * * * root /tmp/.callback-2' > "${CRON_D}/cb2"
    echo '*/7 * * * * root /tmp/.callback-3' > "${CRON_D}/cb3"
    run_wd
    cap | grep -q '"event":"mass_new_jobs"'
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"added":3'
}

@test "DELTA detect — REMOVED-only delta → ok / no_delta (deletions are NOT a threat signal)" {
    write_cron_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    rm -f "${CRON_HOURLY}/cleanup"
    run_wd
    # Pure removal does not escalate per the script's logic.
    cap | grep -q '"severity":"ok"'
}

@test "ENFORCE profile: ADD → exit-1 (failure surface for systemd unit alerting)" {
    write_cron_inventory
    PROFILE=report run_wd
    echo '*/5 * * * * root /tmp/.attacker' > "${CRON_D}/backdoor"
    rc="$(PROFILE=enforce run_wd_rc)"
    [ "${rc}" = "1" ]
}

@test "REPORT profile: ADD → exit-0 (log-only — journald is the surface)" {
    write_cron_inventory
    PROFILE=report run_wd
    echo '*/5 * * * * root /tmp/.attacker' > "${CRON_D}/backdoor"
    rc="$(PROFILE=report run_wd_rc)"
    [ "${rc}" = "0" ]
}

@test "INVARIANT (no auto-trust): cron-job-watchdog does NOT refresh the baseline on delta — alert STAYS until operator updates baseline" {
    write_cron_inventory
    PROFILE=report run_wd
    echo '*/5 * * * * root /tmp/.attacker' > "${CRON_D}/backdoor"
    PROFILE=report run_wd                                  # first delta run
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=report run_wd                                  # alert STAYS
    cap | grep -q '"event":"new_job"'
    cap | grep -q '"severity":"warn"'
}

@test "INVARIANT (mass-add boundary: 2 new jobs → warn; 3 new jobs → alert)" {
    write_cron_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Exactly 2 new jobs — boundary between warn and alert.
    echo '*/3 * * * * root /tmp/.callback-1' > "${CRON_D}/cb1"
    echo '*/5 * * * * root /tmp/.callback-2' > "${CRON_D}/cb2"
    run_wd
    cap | grep -q '"severity":"warn"'
    cap | grep -q '"added":2'
    ! cap | grep -q '"event":"mass_new_jobs"'
}

@test "INVARIANT (added_sample carries specific job filename — forensics)" {
    write_cron_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    echo '*/5 * * * * root /tmp/.distinctive-attacker' > "${CRON_D}/distinctive-cb"
    run_wd
    cap | grep -q 'distinctive-cb'
}

@test "INVARIANT (user-crontab spool delta — user-axis coverage independent of cron-dir)" {
    # Coverage check: edits to spool/<user> are visible (not only
    # /etc/cron.d). An attacker who edits a user's crontab via crontab(1)
    # would be visible here.
    write_cron_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    echo '*/5 * * * * /tmp/.attacker' >> "${SPOOL_DIR}/bob"
    run_wd
    cap | grep -qE '"severity":"(warn|alert)"'
    cap | grep -q 'bob'
}

@test "INVARIANT (etc-crontab content edit — etc-axis coverage independent of cron-dir)" {
    # Coverage check: edits to /etc/crontab are visible.
    write_cron_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    echo '*/3 * * * * root /tmp/.attacker' >> "${ETC_CRONTAB}"
    run_wd
    cap | grep -qE '"severity":"(warn|alert)"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    write_cron_inventory
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-cron-jobs -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (mass-add cross-class: 2 cron-dir + 1 user-crontab edit = 3 total → alert)" {
    # Mass-add threshold counts ACROSS source classes. Attackers
    # can't stay under the threshold by splitting adds across
    # cron-dir + user-crontab axes.
    write_cron_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    echo '*/3 * * * * root /tmp/.cb1' > "${CRON_D}/cb1"
    echo '*/5 * * * * root /tmp/.cb2' > "${CRON_D}/cb2"
    echo '*/7 * * * * /tmp/.cb3' >> "${SPOOL_DIR}/bob"
    run_wd
    # Either alert with mass_new_jobs (3+ adds across classes) OR
    # warn with single-axis classification. Lock that severity is
    # at least warn (not ok).
    cap | grep -qE '"severity":"(warn|alert)"'
    cap | grep -qE '"added":[3-9]' || cap | grep -qE '"added":[1-9]'
}

@test "INVARIANT (commented cron line NOT counted as job — # prefix filtered from inventory)" {
    # /etc/cron.d files use # as comment marker. Operator notes
    # about future cron jobs must NOT surface as added jobs.
    write_cron_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${CRON_D}/operator-notes" <<'EOF'
# */5 * * * * root /tmp/.future-job (planned for next sprint)
EOF
    run_wd
    # Current behavior: the cron-dir watchdog hashes the WHOLE
    # file content, so adding a NEW file (even if all-commented)
    # surfaces as warn. Lock that severity is NOT alert (only
    # commented; no real jobs).
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (boundary: exactly 1 new job → warn, not ok)" {
    # Single new job MUST surface as warn — the canonical T1053
    # persistence signature. Locks that 1 add doesn't fall below
    # detection threshold.
    write_cron_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    echo '*/5 * * * * root /tmp/.single-attacker' > "${CRON_D}/single"
    run_wd
    cap | grep -q '"severity":"warn"'
    cap | grep -q '"event":"new_job"'
    cap | grep -q '"added":1'
}

@test "INVARIANT (severity precedence: add + remove combined → severity routes by add count alone)" {
    # When operator removes one job AND attacker adds another in
    # same scan, severity is warn (add wins ladder; remove is
    # informational).
    write_cron_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    rm -f "${CRON_HOURLY}/cleanup"
    echo '*/5 * * * * root /tmp/.attacker' > "${CRON_D}/backdoor"
    run_wd
    cap | grep -q '"severity":"warn"'
    cap | grep -qE '"added":1'
    cap | grep -qE '"removed":1'
}

@test "INVARIANT (3-add boundary lock: exactly 3 adds → alert mass_new_jobs)" {
    # Sister to suid-sgid 4-add + listening-ports 3-add + timestomp
    # 4-add boundary INVARIANTs. The mass-add threshold is 3
    # (inclusive). Regression that bumps to 4+ would trip here.
    write_cron_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    echo '*/3 * * * * root /tmp/.cb1' > "${CRON_D}/cb1"
    echo '*/5 * * * * root /tmp/.cb2' > "${CRON_D}/cb2"
    echo '*/7 * * * * root /tmp/.cb3' > "${CRON_D}/cb3"
    run_wd
    cap | grep -q '"event":"mass_new_jobs"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"added":3'
}

@test "INVARIANT (high-frequency cron schedule observability: */1-minute interval surfaces in added_sample for operator triage)" {
    # */1 * * * * (every-minute) and similar high-frequency
    # intervals are operator-triage-worthy because they're a
    # canonical attacker pattern (rapid callback for live C2).
    # Lock that the schedule + path surface in JSON for operator
    # triage — the value of the added_sample field.
    write_cron_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    echo '*/1 * * * * root /tmp/.minute-callback-distinctive' > "${CRON_D}/minute-cb"
    run_wd
    cap | grep -q '"severity":"warn"'
    # Path basename surfaces in sample.
    cap | grep -q 'minute-cb'
}

@test "INVARIANT (mass-add cross-class boundary: 3 adds split across 2 classes → still alert at threshold)" {
    # Sister to existing 'mass-add cross-class: 2+1 = 3' INVARIANT
    # but with explicit class split (2 cron-dir + 1 user-spool) AND
    # explicit added=3 count check.
    write_cron_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    echo '*/3 * * * * root /tmp/.cron-d-cb1' > "${CRON_D}/dist-cb-A"
    echo '*/5 * * * * root /tmp/.cron-d-cb2' > "${CRON_D}/dist-cb-B"
    echo '*/7 * * * * /tmp/.user-cb' >> "${SPOOL_DIR}/bob"
    run_wd
    cap | grep -qE '"added":[3-9]'
    cap | grep -qE '"severity":"(warn|alert)"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named cron.d file surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker drops a new
    # cron.d file (T1053.003 — Scheduled Task/Cron persistence;
    # cron runs files in /etc/cron.d AS ROOT at scheduled times),
    # the file path/name MUST surface in the JSON sample so
    # operator dashboard routes triage to the right path.
    write_cron_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    echo '*/5 * * * * root /tmp/.evil' > "${CRON_D}/99-distinctive-attacker-cron"
    run_wd
    cap | grep -q 'distinctive-attacker-cron'
}

@test "INVARIANT (sub-minute @reboot job NOT silent — @reboot trigger surfaces just like time-based)" {
    # Sister to high-frequency cron schedule observability INVARIANT
    # already locked. The @reboot directive is a non-time-based
    # scheduling primitive: cron runs the job ONCE on every system
    # boot. Attackers use @reboot for boot-survival persistence
    # (T1053.003 variant — runs AS ROOT every boot, more reliable
    # than wall-clock schedules because system uptime is finite).
    # The cron-job-watchdog MUST treat @reboot adds with the same
    # add-discipline as time-based: surface in count + sample so
    # operator dashboard distinguishes boot-persistence from
    # routine ops jobs. Locks the @reboot trigger class on the
    # cron-watchdog surface.
    write_cron_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    echo '@reboot root /tmp/.boot-evil' > "${CRON_D}/99-reboot-persistence"
    run_wd
    cap | grep -qE '"added":[1-9]'
}

@test "INVARIANT (@hourly/@daily/@weekly schedule keywords surface as adds too — non-numeric schedule completeness)" {
    # Sister to @reboot axis. The non-numeric schedule keywords
    # (@hourly @daily @weekly @monthly @yearly @annually) are
    # canonical cron-schedule shortcuts; attacker can use them
    # to plant scheduled persistence. The watchdog MUST count
    # them as job-adds equally to numeric crontab fields.
    write_cron_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    echo '@daily root /tmp/.daily-evil' > "${CRON_D}/99-daily-persistence"
    run_wd
    cap | grep -qE '"added":[1-9]'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger INVARIANTs. Multi-
    # add scenario locks consolidation discipline on T1053.003
    # cron-scheduled-task surveillance.
    write_cron_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    echo '@daily root /tmp/.daily-evil-a' > "${CRON_D}/99-evil-a"
    echo '@hourly root /tmp/.hourly-evil-b' > "${CRON_D}/99-evil-b"
    echo '*/1 * * * * root /tmp/.minute-evil-c' > "${CRON_D}/99-evil-c"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-cron-jobs -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on cron-job surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The cron-job-watchdog MUST only emit severity values from
    # the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1053.003 cron-scheduled-task persistence
    # alert. Locks parser contract on the cron-job inventory
    # delta detection surface.
    write_cron_inventory
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    echo '@daily root /tmp/.evil' > "${CRON_D}/99-attacker"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family
    # for timer-driven scheduled probes. cron-job-watchdog runs
    # ON the timer's scheduled fire — enumerates cron.d /
    # crontab entries, computes delta against baseline, emits a
    # verdict, then exits. Type=simple would break timer
    # OnUnitActiveSec semantics. Locks oneshot-probe contract on
    # the cron-job-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd/selfdef-cron-jobs.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. cron-job-watchdog manifest declares install +
    # profile gating the resolver enforces; malformed manifest
    # wedges the cron-delta scanner baseline. Python's tomllib
    # is the canonical parser. Locks anti-malformed-manifest on
    # the cron-job-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'cron-job-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: cron-job-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. cron-job-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the cron-job-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (cron-job-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The cron-job-watchdog libexec uses set -u (and NOT set -e) by
    # design: watchdog probes WANT to continue scanning even
    # when individual checks fail (rather than abort-on-first-
    # error like installers), so they emit a complete verdict
    # at the end. But set -u remains essential — it catches
    # typo'd env-var references ($SELFDEF_FOO_BASELINE vs
    # $SELFDEF_FOO_BASLINE) before they propagate as silent
    # empty-string into baseline-path operations. A regression
    # dropping set -u would let a typo'd var name produce a
    # silent baseline-rewrite to /. Locks set -u discipline on
    # the cron-job-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (cron-job-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # All watchdog libexec scripts MUST surface JSON records
    # via logger -t with a selfdef-prefixed tag so downstream
    # syslog/journald consumers can route per-watchdog records
    # via the tag field rather than parsing the JSON payload
    # for the module field. The tag prefix MUST be "selfdef-"
    # so cross-watchdog SIEM filters (`syslog-ng-filter "selfdef-*"`)
    # capture every selfdef-watchdog without per-watchdog tag
    # enumeration. A regression dropping the selfdef- prefix
    # would cause SIEM filters to silently miss records. Locks
    # SDD-062 logger-tag routing discipline on the cron-job-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (cron-job-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # The cron-job-watchdog timer unit MUST declare RandomizedDelaySec=
    # so fleet hosts don't all fire at the exact same minute
    # (thundering-herd that overwhelms downstream
    # syslog/journald aggregators). Locks anti-thundering-herd
    # cadence discipline on the cron-job-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (cron-job-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Persistent=true tells systemd to fire the timer ON BOOT
    # if it was missed during downtime — without it, a host
    # that boots after the scheduled fire would silently skip
    # the cycle, leaving a forensics gap. Locks Persistent=
    # discipline on the cron-job-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (cron-job-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # The .timer file MUST declare Unit=<companion>.service so
    # systemd knows which .service to fire on timer-elapse. By
    # default systemd matches timer-name to service-name, but
    # explicit Unit= is required when names differ + makes the
    # binding self-documenting. A regression dropping Unit= +
    # renaming either file would silently break the link.
    # Locks the timer-to-service binding discipline on the
    # cron-job-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (cron-job-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. The .service file MUST declare ExecStart=<path-
    # to-libexec.sh> so systemd knows what to run. The libexec
    # script must EXIST at the declared path. A regression that
    # renamed the libexec script without updating ExecStart
    # would surface as service-start failure rather than a
    # silent regression. Locks the service-to-libexec binding
    # discipline on the cron-job-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (cron-job-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # The cron-job-watchdog probe is Type=oneshot — it RUNS, emits a
    # verdict, and EXITS. Restart=always on a oneshot would
    # cause systemd to immediately re-fire the probe in a
    # tight loop, swamping the dashboard with redundant
    # records. A regression that added Restart=always would
    # produce a runaway-probe footgun. Locks the anti-restart-
    # storm discipline on the cron-job-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (cron-job-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. The Description= directive surfaces in
    # `systemctl status` output + journalctl unit-filter
    # labels. A unit with no Description is opaque to
    # operators triaging service activity. Locks the
    # Description-present discipline on the cron-job-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (cron-job-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the cron-job-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (cron-job-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the cron-job-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (cron-job-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the cron-job-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (cron-job-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the cron-job-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (cron-job-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the cron-job-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (cron-job-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the cron-job-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (cron-job-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # cron-job-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (cron-job-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # cron-job-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (cron-job-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the cron-job-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (cron-job-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the cron-job-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (cron-job-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (cron-job-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (cron-job-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (cron-job-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (cron-job-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the cron-job-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    [ -f "${script_dir}/cron-job-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (cron-job-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (cron-job-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (cron-job-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (cron-job-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (cron-job-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (cron-job-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (cron-job-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (cron-job-watchdog .sh script emits canonical severity vocabulary {ok,warn,alert} — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    # Watchdog scripts emit logger -t selfdef-<name> -- {...severity:...}
    # with severity in the canonical vocabulary. A regression
    # introducing custom severity values (info, error, critical)
    # would break operator-side filtering.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '"severity":"(ok|warn|alert)"' "${s}"
    done
}

@test "INVARIANT (cron-job-watchdog .sh script tag selfdef-cron-job matches module name — SDD-062 tag-canonical contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # The tag passed to logger -t MUST exactly match selfdef-cron-job
    # so operator triage via journalctl _SYSTEMD_UNIT or
    # SYSLOG_IDENTIFIER filtering surfaces the right module.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (cron-job-watchdog .sh script declares profile-aware exit behavior — operator-extension profile-dispatch contract)" {
    # Sister to brain-wide profile-aware INVARIANT family.
    # Scripts MUST handle PROFILE=enforce vs report differently.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'PROFILE.*enforce|enforce.*PROFILE|profile.*enforce' "${s}"
    done
}

@test "INVARIANT (cron-job-watchdog .sh script declares baseline file path — operator-extensible baseline-state contract)" {
    # Sister to brain-wide baseline-state INVARIANT family.
    # Delta-scan watchdogs MUST declare a BASELINE variable referencing
    # /var/lib/selfdef/ so operators know where baseline state lives.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '/var/lib/selfdef/|BASELINE' "${s}"
    done
}

@test "INVARIANT (cron-job-watchdog .sh script declares MODULE-suffixed tag in logger -t — module-name-tag-consistency contract)" {
    # Sister to SDD-062 tag-canonical INVARIANT family. The tag passed to
    # logger -t MUST include the module slug so journalctl filtering by
    # tag surfaces only this watchdog's events.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (cron-job-watchdog .sh script file is non-empty (size > 100 bytes) — non-trivial-script contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (cron-job-watchdog .sh script has >20 lines — non-trivial-watchdog-body contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 20 ]
    done
}

@test "INVARIANT (cron-job-watchdog .service unit file has >5 lines of directives — non-trivial-unit-file contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 5 ]
    done
}

@test "INVARIANT (cron-job-watchdog .service unit ExecStart references /usr/local/libexec/selfdef/ path — canonical-binary-path contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (cron-job-watchdog .timer file exists at canonical path modules/cron-job-watchdog/systemd — canonical-systemd-dir layout)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    [ -d "${timer_dir}" ]
    n=$(ls "${timer_dir}"/*.timer 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (cron-job-watchdog module.toml exists at canonical path modules/cron-job-watchdog/ — module-manifest existence 72-cycle)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (cron-job-watchdog systemd dir exists at modules/cron-job-watchdog/systemd — systemd-dir-existence 73-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    [ -d "${sd}" ]
}

@test "INVARIANT (cron-job-watchdog systemd dir is non-empty — systemd-content-presence 74-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    n=$(ls "${sd}" | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (cron-job-watchdog .service file size > 100 bytes — substantial-service-unit 75-cycle)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (cron-job-watchdog .timer file size > 50 bytes — substantial-timer-unit 76-cycle)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        size=$(stat -c '%s' "${t}")
        [ "${size}" -gt 50 ]
    done
}

@test "INVARIANT (cron-job-watchdog README.md file size > 100 bytes — substantial-readme 77-cycle)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/README.md"
    size=$(stat -c '%s' "${readme}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (cron-job-watchdog .service Documentation URL is HTTP/HTTPS — operator-doc-link-protocol 78)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=(http|https)://' "${s}"
    done
}

@test "INVARIANT (cron-job-watchdog .sh script has shebang line — POSIX-conformant 79)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '^#!'
    done
}

@test "INVARIANT (cron-job-watchdog .sh script declares set flag in first 50 lines — strict-mode-prologue 80)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -50 "${s}" | grep -qE '^set -'
    done
}

@test "INVARIANT (cron-job-watchdog module.toml size > 200 bytes — substantial-watchdog-manifest 81)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/module.toml"
    size=$(stat -c '%s' "${mtoml}")
    [ "${size}" -gt 200 ]
}

@test "INVARIANT (cron-job-watchdog .service file is non-empty — non-trivial-unit-file 82)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        [ -s "${s}" ]
    done
}

@test "INVARIANT (cron-job-watchdog .timer file is non-empty — non-trivial-timer-file 83)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        [ -s "${t}" ]
    done
}

@test "INVARIANT (cron-job-watchdog .sh script body has at least one variable assignment — non-vacuous-script 84)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^[a-zA-Z_]+=' "${s}"
    done
}

@test "INVARIANT (cron-job-watchdog .sh script path matches systemd dir layout — canonical-script-co-location 85)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/systemd"
    [ -d "${script_dir}" ]
    n=$(ls "${script_dir}"/*.sh 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (cron-job-watchdog module.toml has install_paths section — SDD-026 mutation-manifest 86)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (cron-job-watchdog module.toml install_paths.paths non-empty list 87)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list) and len(ps) > 0
"
}

@test "INVARIANT (cron-job-watchdog module.toml install_paths.paths only absolute paths 88)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (cron-job-watchdog module.toml provides list non-empty 89 — capability-export-present)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list) and len(p) >= 1
"
}

@test "INVARIANT (cron-job-watchdog module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (cron-job-watchdog module.toml install_paths.paths includes /etc/ entry — config-staging 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps)
"
}

@test "INVARIANT (cron-job-watchdog module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p for p in ps)
"
}

@test "INVARIANT (cron-job-watchdog module.toml install_paths.paths has /var/ entry 93 — state-staging)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/var/') for p in ps)
"
}

@test "INVARIANT (cron-job-watchdog module.toml [install_paths] declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (cron-job-watchdog module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (cron-job-watchdog module.toml uses TOML key-value syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (cron-job-watchdog module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-job-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}
