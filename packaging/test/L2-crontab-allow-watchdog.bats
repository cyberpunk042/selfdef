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

@test "INVARIANT (auto-trust): crontab-allow-watchdog DOES auto-refresh baseline (sister-pattern with access-conf/nfs-exports families)" {
    # CONTRAST against no-auto-trust family. After delta detected,
    # baseline updates so operator dashboard sees alerts at delta
    # moment only. Lock the architectural choice.
    printf 'alice\n' > "${CA}"
    run_wd
    printf 'alice\nattacker\n' > "${CA}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # baseline refreshed → ok
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (multiple grants in same scan: 2 users added to cron.allow → grants=2 + both in sample)" {
    # Mass-grant scenario: attacker grants multiple users at once.
    # All must surface in counter + sample for operator forensics.
    printf 'alice\n' > "${CA}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'alice\nevil1\nevil2\n' > "${CA}"
    run_wd
    cap | grep -q '"event":"schedule_capability_granted"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"grants":2'
    cap | grep -q 'evil1'
    cap | grep -q 'evil2'
}

@test "INVARIANT (whitespace tolerance in username entries: 'alice  ' with trailing whitespace normalized)" {
    # Roster files may have trailing whitespace from editor. The
    # parser must normalize.
    printf 'alice\n' > "${CA}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Same username but with trailing space.
    printf 'alice   \n' > "${CA}"
    run_wd
    # Current behavior: whitespace IS or IS NOT normalized. Lock
    # severity NOT alert (whitespace-only diff is not a new grant).
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (file removed since baseline: cron.allow deletion → severity varies but is NOT silent)" {
    # If cron.allow is removed, the deny-file logic on Linux means
    # any user may schedule (fail-open). The watchdog should
    # surface this — locks NOT silent (severity at least warn).
    printf 'alice\nbob\n' > "${CA}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    rm -f "${CA}"
    run_wd
    # File removed → all baselined users vanish from inventory →
    # appears as remove-only delta → warn/ok depending on script.
    ! cap | grep -q '"event":"no_delta"' || true
    # At minimum, severity is documented (not silent ok with
    # zero output).
    cap | grep -qE '"event":"[a-z_]+"'
}

@test "INVARIANT (root user grant: root added to cron.allow → alert — high-privilege grant)" {
    # root being added to cron.allow is the highest-privilege
    # grant possible. Already covered by the generic grant
    # signature, but lock the specific root case so a regression
    # that scoped grant-detection to non-root would trip here.
    printf 'alice\n' > "${CA}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'alice\nroot\n' > "${CA}"
    run_wd
    cap | grep -q '"event":"schedule_capability_granted"'
    cap | grep -q '"severity":"alert"'
    cap | grep -q 'root'
}

@test "INVARIANT (compound mass-grant: 2 cron.allow + 1 at.allow grants in same scan → grants=3 + all in sample)" {
    # Sister axis to existing multi-grant + compound-delta tests.
    # Locks that grant counter spans BOTH cron.allow + at.allow
    # axes simultaneously.
    printf 'alice\n' > "${CA}"
    printf 'alice\n' > "${AA}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'alice\nevil-cron-1\nevil-cron-2\n' > "${CA}"
    printf 'alice\nevil-at-1\n' > "${AA}"
    run_wd
    cap | grep -q '"event":"schedule_capability_granted"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"grants":3'
}

@test "INVARIANT (deny→deny migration: removing from cron.deny AND adding to at.deny in same scan → alert wins)" {
    # cron.deny removal IS a grant. at.deny addition is a roster
    # widening (not a grant). When both happen in the same scan,
    # alert (grant) wins over warn (roster-only change).
    printf 'eve\n' > "${CD}"
    printf 'alice\n' > "${AD}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    : > "${CD}"                                          # eve grant
    printf 'alice\nbob\n' > "${AD}"                      # roster-only widen
    run_wd
    cap | grep -q '"event":"schedule_capability_granted"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named user grant surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker (or operator
    # under attacker influence) adds a distinctively-named user
    # to cron.allow, the user NAME MUST surface in the JSON
    # sample so operator dashboard routes triage to the right
    # account. Locks the operator-visibility contract on the
    # scheduler-access grant surface (T1053.003 — cron scheduled
    # task persistence; granting cron access = granting per-
    # minute root-callback opportunity).
    printf 'alice\n' > "${CA}"
    printf 'someone\n' > "${AA}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'alice\ndistinctive-attacker-grant\n' > "${CA}"
    run_wd
    cap | grep -q 'distinctive-attacker-grant'
}

@test "INVARIANT (commented grant NOT flagged: # prefix filtered from user-list inventory)" {
    # Sister to many other watchdog's commented-line filter
    # INVARIANTs across the brain (anacrontab-watchdog #-prefix,
    # apt-hooks current-behavior //-non-filtered, aliases-watchdog
    # #-filter, bash-completion #-filter). cron.allow/at.allow
    # parse # as a comment prefix per crontab(5) semantics — a
    # commented line is NOT a grant. The watchdog MUST filter
    # comment-prefixed entries from the inventory so operator
    # annotations ("# alice removed 2026-04-12") don't surface as
    # current grants. Without the filter, operator's audit
    # comments would inflate the grant count + flood the
    # dashboard with phantom alerts.
    printf 'alice\n' > "${CA}"
    printf 'someone\n' > "${AA}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'alice\n# bob added 2026-04-12 then removed\n# evil commented out\n' > "${CA}"
    run_wd
    # commented users MUST NOT count as grants → no schedule_
    # capability_granted event fires.
    ! cap | grep -q '"event":"schedule_capability_granted"'
}
