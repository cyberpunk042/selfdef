#!/usr/bin/env bats
# L2 functional suite for crontab-allow-watchdog.
#
# crontab-allow-watchdog tracks who-may-schedule via the
# /etc/{cron,at}.{allow,deny} roster files. A capability GRANT
# fires alert / schedule_capability_granted:
#   - a user ADDED to cron.allow / at.allow      (explicit grant)
#   - a user REMOVED from cron.deny / at.deny    (deny removed → permits)
# Roster touched without a grant fires warn / schedule_roster_changed.
#
# Uses the SELFDEF_CRONALLOW_FILES env-var override (added 2026-06-06)
# to point the watchdog at fixture files rather than /etc/{cron,at}.{allow,deny}.
#
# Run with: bats packaging/test/L2-crontab-allow-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd/crontab-allow-watchdog.sh"

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
    BASELINE="${TMP}/crontab-allow-baseline.tsv"
    CA="${TMP}/cron.allow"
    CD="${TMP}/cron.deny"
    AA="${TMP}/at.allow"
    AD="${TMP}/at.deny"
    FILES="${CA}:${CD}:${AA}:${AD}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_CRONALLOW_PROFILE="${PROFILE:-report}" \
    SELFDEF_CRONALLOW_BASELINE="${BASELINE}" \
    SELFDEF_CRONALLOW_FILES="${FILES}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "first run with no roster files → baseline_initial with 0 entries" {
    # None of the fixture files exist.
    run_wd
    [ -f "${BASELINE}" ]
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"entries":0'
}

@test "first run with roster files captures inventory + chmod 0600" {
    printf 'alice\n' > "${CA}"
    printf 'eve\n'   > "${CD}"
    run_wd
    [ -f "${BASELINE}" ]
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"entries":2'    # alice + eve
    # TSV well-formed
    awk -F'\t' 'NF==2{ok=1} END{exit ok?0:1}' "${BASELINE}"
}

@test "unchanged roster on second run → ok / no_delta" {
    printf 'alice\n' > "${CA}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
    cap | grep -qE '"grants":0'
}

@test "user ADDED to cron.allow → alert / schedule_capability_granted (the grant signature)" {
    printf 'alice\n' > "${CA}"
    run_wd                          # baseline = {cron.allow:alice}
    printf 'alice\nbackdoor_user\n' > "${CA}"     # capability grant
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"schedule_capability_granted"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"grants":1'
}

@test "user ADDED to at.allow → alert / schedule_capability_granted" {
    printf 'alice\n' > "${AA}"
    run_wd
    printf 'alice\neve\n' > "${AA}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"schedule_capability_granted"'
    cap | grep -qE '"grants":1'
}

@test "user REMOVED from cron.deny → alert / schedule_capability_granted (deny-removed-permits)" {
    # cron.deny exists; eve is denied. Remove eve from cron.deny → eve
    # is no longer denied → capability granted to eve.
    printf 'eve\n' > "${CD}"
    run_wd
    : > "${CD}"   # eve removed from deny
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"schedule_capability_granted"'
    cap | grep -qE '"grants":1'
}

@test "user ADDED to cron.deny (denial widened, NOT a grant) → warn / schedule_roster_changed" {
    printf 'alice\n' > "${CD}"
    run_wd                          # baseline = {cron.deny:alice}
    printf 'alice\nbob\n' > "${CD}"  # bob now ALSO denied — NOT a grant
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"schedule_roster_changed"'
    cap | grep -q '"severity":"warn"'
    cap | grep -qE '"grants":0'
}

@test "user REMOVED from cron.allow (capability REVOKED, not granted) → warn / schedule_roster_changed" {
    printf 'alice\nbob\n' > "${CA}"
    run_wd                          # baseline = {alice, bob}
    printf 'alice\n' > "${CA}"      # bob removed — bob's grant revoked, NOT a new grant
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"schedule_roster_changed"'
    cap | grep -q '"severity":"warn"'
    cap | grep -qE '"grants":0'
}

@test "the emitted JSON carries every promised schema field" {
    printf 'alice\n' > "${CA}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'alice\nbob\n' > "${CA}"
    run_wd
    line="$(cap)"
    printf '%s' "${line}" | grep -q '"tag":"selfdef-crontab-allow"'
    printf '%s' "${line}" | grep -q '"severity":'
    printf '%s' "${line}" | grep -q '"event":'
    printf '%s' "${line}" | grep -q '"profile":'
    printf '%s' "${line}" | grep -qE '"added":[0-9]+'
    printf '%s' "${line}" | grep -qE '"removed":[0-9]+'
    printf '%s' "${line}" | grep -qE '"grants":[0-9]+'
    printf '%s' "${line}" | grep -q '"added_sample":'
    printf '%s' "${line}" | grep -q '"removed_sample":'
}

@test "enforce profile + capability grant → exit 1" {
    printf 'alice\n' > "${CA}"
    run_wd
    printf 'alice\neve\n' > "${CA}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PATH="${BIN}:${PATH}" \
        SELFDEF_CRONALLOW_PROFILE=enforce \
        SELFDEF_CRONALLOW_BASELINE="${BASELINE}" \
        SELFDEF_CRONALLOW_FILES="${FILES}" \
        bash "${WD}" && fail "enforce + capability grant should exit non-zero"
    cap | grep -q '"event":"schedule_capability_granted"'
}

@test "INVARIANT (user ADDED to at.allow uses the SAME grant signature as cron.allow): roster-axis-symmetric" {
    # Two parallel allow-rosters; both must fire the same grant signature
    # so SDD-062 downstream consumer doesn't need axis-aware routing.
    printf 'alice\n' > "${AA}"
    run_wd
    printf 'alice\nattacker\n' > "${AA}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"schedule_capability_granted"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (user REMOVED from at.deny → alert, parallel to cron.deny semantic)" {
    printf 'eve\n' > "${AD}"
    run_wd
    : > "${AD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"schedule_capability_granted"'
}

@test "INVARIANT (compound delta — grant AND roster-only change simultaneously → alert; the grant wins)" {
    # Realistic operator-edit + attacker-grant in the same diff.
    printf 'alice\n' > "${CA}"
    printf 'bob\n'   > "${CD}"
    run_wd
    printf 'alice\nattacker\n' > "${CA}"     # GRANT
    printf 'bob\ncarol\n'      > "${CD}"     # roster-only widen
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"schedule_capability_granted"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (DELTA-detect: ADDED-user surfaces in added_sample by name)" {
    printf 'alice\n' > "${CA}"
    run_wd
    printf 'alice\ndistinctive-attacker\n' > "${CA}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q 'distinctive-attacker'
}

@test "INVARIANT (comment lines in roster are ignored — # is not a user)" {
    # cron.allow may carry comments; the delta should ignore them.
    printf 'alice\n' > "${CA}"
    run_wd
    printf 'alice\n# this is a comment\n' > "${CA}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    # No new GRANT — the comment shouldn't surface as a granted user.
    cap | grep -q '"severity":"ok"'
    cap | grep -q '"event":"no_delta"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf 'alice\n' > "${CA}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-crontab-allow -- ')
    [ "${main_count}" = "1" ]
}
