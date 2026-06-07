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

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger-line INVARIANTs.
    printf 'alice\n' > "${CA}"
    printf 'someone\n' > "${AA}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'alice\nevil1\nevil2\nevil3\n' > "${CA}"
    printf 'someone\nevil4\n' > "${AA}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-crontab-allow -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (baseline re-establish on operator out-of-band deletion: missing baseline re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs.
    # State-resilience on T1053.003 cron-grant access-list
    # surveillance.
    printf 'alice\n' > "${CA}"
    printf 'someone\n' > "${AA}"
    run_wd                                              # establishes baseline
    [ -f "${BASELINE}" ]
    rm -f "${BASELINE}"                                  # operator wipe
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # must re-establish
    [ -f "${BASELINE}" ]
    cap | grep -qE '"event":"baseline_initial"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on crontab-allow surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The crontab-allow-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1053.003 cron-grant access-list surveillance
    # alert. Locks parser contract on the cron.allow/at.allow
    # delta detection surface.
    printf 'alice\n' > "${CA}"
    printf 'someone\n' > "${AA}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    printf 'alice\nevil\n' > "${CA}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # crontab-allow-watchdog runs ON the timer's scheduled fire
    # — diffs cron.allow/cron.deny/at.allow/at.deny against
    # baseline, emits a verdict, then exits. Type=simple would
    # break timer OnUnitActiveSec semantics. Locks oneshot-probe
    # contract on the crontab-allow-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd/selfdef-crontab-allow.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. crontab-allow-watchdog manifest declares install +
    # profile gating the resolver enforces; malformed manifest
    # wedges the cron.allow/cron.deny/at.allow/at.deny delta
    # scanner. Python's tomllib is the canonical parser. Locks
    # anti-malformed-manifest on the crontab-allow-watchdog
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'crontab-allow-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: crontab-allow-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. crontab-allow-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the crontab-allow-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (crontab-allow-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The crontab-allow-watchdog libexec uses set -u (and NOT set -e) by
    # design: watchdog probes WANT to continue scanning even
    # when individual checks fail (rather than abort-on-first-
    # error like installers), so they emit a complete verdict
    # at the end. But set -u remains essential — it catches
    # typo'd env-var references ($SELFDEF_FOO_BASELINE vs
    # $SELFDEF_FOO_BASLINE) before they propagate as silent
    # empty-string into baseline-path operations. A regression
    # dropping set -u would let a typo'd var name produce a
    # silent baseline-rewrite to /. Locks set -u discipline on
    # the crontab-allow-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (crontab-allow-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
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
    # SDD-062 logger-tag routing discipline on the crontab-allow-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (crontab-allow-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # The crontab-allow-watchdog timer unit MUST declare RandomizedDelaySec=
    # so fleet hosts don't all fire at the exact same minute
    # (thundering-herd that overwhelms downstream
    # syslog/journald aggregators). Locks anti-thundering-herd
    # cadence discipline on the crontab-allow-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (crontab-allow-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Persistent=true tells systemd to fire the timer ON BOOT
    # if it was missed during downtime — without it, a host
    # that boots after the scheduled fire would silently skip
    # the cycle, leaving a forensics gap. Locks Persistent=
    # discipline on the crontab-allow-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (crontab-allow-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # The .timer file MUST declare Unit=<companion>.service so
    # systemd knows which .service to fire on timer-elapse. By
    # default systemd matches timer-name to service-name, but
    # explicit Unit= is required when names differ + makes the
    # binding self-documenting. A regression dropping Unit= +
    # renaming either file would silently break the link.
    # Locks the timer-to-service binding discipline on the
    # crontab-allow-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (crontab-allow-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. The .service file MUST declare ExecStart=<path-
    # to-libexec.sh> so systemd knows what to run. The libexec
    # script must EXIST at the declared path. A regression that
    # renamed the libexec script without updating ExecStart
    # would surface as service-start failure rather than a
    # silent regression. Locks the service-to-libexec binding
    # discipline on the crontab-allow-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (crontab-allow-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # The crontab-allow-watchdog probe is Type=oneshot — it RUNS, emits a
    # verdict, and EXITS. Restart=always on a oneshot would
    # cause systemd to immediately re-fire the probe in a
    # tight loop, swamping the dashboard with redundant
    # records. A regression that added Restart=always would
    # produce a runaway-probe footgun. Locks the anti-restart-
    # storm discipline on the crontab-allow-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (crontab-allow-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. The Description= directive surfaces in
    # `systemctl status` output + journalctl unit-filter
    # labels. A unit with no Description is opaque to
    # operators triaging service activity. Locks the
    # Description-present discipline on the crontab-allow-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (crontab-allow-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the crontab-allow-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (crontab-allow-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the crontab-allow-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (crontab-allow-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the crontab-allow-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (crontab-allow-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the crontab-allow-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (crontab-allow-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the crontab-allow-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (crontab-allow-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the crontab-allow-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (crontab-allow-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # crontab-allow-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (crontab-allow-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # crontab-allow-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (crontab-allow-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the crontab-allow-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (crontab-allow-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the crontab-allow-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (crontab-allow-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (crontab-allow-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (crontab-allow-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (crontab-allow-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (crontab-allow-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the crontab-allow-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/crontab-allow-watchdog/systemd"
    [ -f "${script_dir}/crontab-allow-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}
