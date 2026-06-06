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
