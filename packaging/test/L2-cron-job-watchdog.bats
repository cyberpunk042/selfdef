#!/usr/bin/env bats
# L2 functional + capture-regression suite for cron-job-watchdog.
#
# cron-job-watchdog inventories every user crontab, /etc/crontab, the cron.d
# / cron.{hourly,daily,weekly,monthly} drop-ins, and enabled systemd timers
# (hashing each so a changed OnCalendar/ExecStart is caught) into a baseline,
# then alerts on a new/changed job. It reads those system paths directly (no
# input-source knob), so what this suite locks is the inventory-CAPTURE
# regression: the scan must actually write its records into the baseline it
# diffs — the 2026-05-27 bug where `emit_file`'s `printf` went to stdout
# instead of `$current`, leaving the baseline empty and every diff a no-op.
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
    export SELFDEF_TEST_LOGCAP="${TMP}/log.out"
    : > "${SELFDEF_TEST_LOGCAP}"
    BASELINE="${TMP}/cron-jobs-baseline.tsv"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_CRONJOBS_PROFILE="${PROFILE:-report}" \
    SELFDEF_CRONJOBS_BASELINE="${BASELINE}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# Only the non-empty-capture lock is data-dependent: the bug produces an empty
# baseline EVEN WHEN cron sources exist, but a genuinely cron-less host also
# yields an empty baseline legitimately. Gate those asserts on real sources so
# the test is deterministic (locks the bug where it can fire, never false-fails).
have_cron_sources() {
    [ -s /etc/crontab ] || [ -n "$(ls -A /etc/cron.d 2>/dev/null)" ] \
        || [ -n "$(ls -A /var/spool/cron/crontabs 2>/dev/null)" ]
}

@test "first run captures the cron inventory into the baseline (non-empty)" {
    have_cron_sources || skip "no cron sources on this host to inventory"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
    [ -s "${BASELINE}" ]                                  # capture regression lock
    # records are <source>\t<path>\t<sha> — at least one well-formed TSV row.
    awk -F'\t' 'NF>=3{ok=1} END{exit ok?0:1}' "${BASELINE}"
}

@test "the baseline is reported with a non-zero count (records reached \$current)" {
    have_cron_sources || skip "no cron sources on this host to inventory"
    run_wd
    # baseline_count:0 was the exact symptom of the stdout-leak bug.
    cap | grep -qE '"baseline_count":[1-9][0-9]*'
}

@test "unchanged cron state on second run -> ok / no_delta" {
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
}
