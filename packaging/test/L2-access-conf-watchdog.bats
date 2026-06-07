#!/usr/bin/env bats
# L2 bats functional tests for the access-conf-watchdog scan script.
#
# /etc/security/access.conf (pam_access) gates logins by user + origin. A
# permit (`+`) rule from a broad/ALL origin is a backdoor-access signature.
# Severity:
#   ok    → no delta
#   warn  → any rule added/removed/changed
#   alert → a `+` permit rule whose origin is ALL/broad
#
# Run with: bats packaging/test/L2-access-conf-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/access-conf-watchdog/systemd/access-conf-watchdog.sh"

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
    CONF="${TMP}/access.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_ACCESSCONF_PROFILE="${PROFILE:-report}" \
    SELFDEF_ACCESSCONF_BASELINE="${BASELINE}" \
    SELFDEF_ACCESSCONF_FILE="${CONF_V:-$CONF}" \
    SELFDEF_ACCESSCONF_D="${TMP}/no-access-d" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '+ : root : LOCAL\n- : ALL : ALL\n' > "${CONF}"
}

@test "no access.conf → ok / no_access_conf" {
    CONF_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_access_conf"'
    cap | grep -q '"severity":"ok"'
}

@test "benign access.conf, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged access.conf on second run → ok / access_conf_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"access_conf_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a + permit from ALL → alert / access_conf_broad_permit" {
    seed_benign
    run_wd
    printf '+ : root : LOCAL\n+ : backdoor : ALL\n- : ALL : ALL\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"access_conf_broad_permit"'
    cap | grep -q '"severity":"alert"'
}

@test "a benign rule change → warn / access_conf_changed" {
    seed_benign
    run_wd
    printf '+ : root : LOCAL\n+ : admins : 192.168.1.0/24\n- : ALL : ALL\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"access_conf_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign LOCAL-only access.conf is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "enforce profile exits non-zero on a broad permit" {
    seed_benign
    run_wd
    printf '+ : backdoor : ALL\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — access.conf inventory enumerates login-grant identities)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (pre-existing broad permit): baseline_initial fires alert if access.conf already has `+ ... : ALL` at install-time" {
    # The watchdog flags broad permits in the BASELINE-INITIAL
    # event too, so the operator sees existing risk at install
    # time. Locks the install-time vetting contract.
    printf '+ : root : LOCAL\n+ : remote-svc : ALL\n- : ALL : ALL\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (existing broad permit is NOT re-alerted): the same broad permit in baseline + current → ok / access_conf_intact" {
    # A broad permit that pre-existed at baseline-creation time
    # lives in BOTH the baseline and current; the script flags
    # only NEW broad permits (the `added` set), so the next run
    # is intact. Locks the no-spurious-re-alert contract.
    printf '+ : svc : ALL\n- : ALL : ALL\n' > "${CONF}"
    run_wd                                              # baseline includes broad permit
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # broad permit STILL present
    cap | grep -q '"event":"access_conf_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "DELTA detect — REMOVED rule (operator pruning) → warn / access_conf_changed" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # printf with leading `-` needs -- separator; use %s instead to sidestep.
    printf '%s\n' '- : ALL : ALL' > "${CONF}"          # remove the root LOCAL permit
    run_wd
    cap | grep -q '"event":"access_conf_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "added/removed/suspicious counts surface in JSON (operator triage observability)" {
    seed_benign
    run_wd
    printf '%s\n' '+ : root : LOCAL' '+ : backdoor : ALL' '- : ALL : ALL' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    # 1 add (backdoor:ALL), maybe 0 removes.
    cap | grep -qE '"added":[1-9]'
    cap | grep -q '"suspicious":"permit:backdoor:from-ALL"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-access-conf -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (auto-trust): access-conf-watchdog DOES auto-refresh the baseline (operator-action common)" {
    # CONTRAST against the no-auto-trust family. access.conf
    # changes ARE common operator action (adding sysadmin allow-
    # lists, restricting login origins). The watchdog flags the
    # delta for THIS run; the baseline catches up on the next.
    # Locks the asymmetry against a regression that copies the
    # no-auto-trust pattern here.
    seed_benign
    run_wd
    printf '+ : admins : 192.168.1.0/24\n- : ALL : ALL\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — warn
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # baseline refreshed
    cap | grep -q '"event":"access_conf_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (deny (-) rule with broad origin is NOT flagged): deny ALL : ALL is the canonical default-deny floor" {
    # The whole point of a default-deny floor is `- : ALL : ALL`
    # — must not be flagged as a backdoor. Lock the contract that
    # ONLY permit (+) rules count toward broad-permit detection.
    printf '+ : root : LOCAL\n- : malicious : ALL\n- : ALL : ALL\n' > "${CONF}"
    run_wd                                              # baseline
    : > "${SELFDEF_TEST_LOGCAP}"
    # Operator widens the deny — still safe.
    printf '+ : root : LOCAL\n- : another-malicious : ALL\n- : ALL : ALL\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented + permit line is NOT flagged — # prefix filtered)" {
    # An operator-commented note about a future permit must not
    # appear in the parsed rule inventory at all.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '+ : root : LOCAL\n# + : remote-svc : ALL\n- : ALL : ALL\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (suspicious sample format: permit:USER:from-ALL — operator-readable triage payload)" {
    # The sample field shape is permit:USER:from-ALL — the
    # downstream alerting hook renders this directly to operator
    # email. Lock the format so dashboards don't break on shape
    # change.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '+ : root : LOCAL\n+ : backdoor-svc : ALL\n- : ALL : ALL\n' > "${CONF}"
    run_wd
    cap | grep -qE '"suspicious":"permit:backdoor-svc:from-ALL'
}

@test "INVARIANT (access.conf.d drop-in axis: broad permit in drop-in → alert; not only main /etc/security/access.conf scanned)" {
    # The script walks SELFDEF_ACCESSCONF_D for *.conf drop-ins.
    # An attacker can plant the backdoor permit in
    # /etc/security/access.d/00-evil.conf to avoid touching the
    # main file. Watchdog must walk the drop-in dir too.
    ACCESSD="${TMP}/access.d"
    mkdir -p "${ACCESSD}"
    seed_benign
    PATH="${BIN}:${PATH}" \
        SELFDEF_ACCESSCONF_PROFILE="report" \
        SELFDEF_ACCESSCONF_BASELINE="${BASELINE}" \
        SELFDEF_ACCESSCONF_FILE="${CONF}" \
        SELFDEF_ACCESSCONF_D="${ACCESSD}" \
        bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant the evil drop-in.
    printf '+ : evil-svc : ALL\n' > "${ACCESSD}/00-evil.conf"
    PATH="${BIN}:${PATH}" \
        SELFDEF_ACCESSCONF_PROFILE="report" \
        SELFDEF_ACCESSCONF_BASELINE="${BASELINE}" \
        SELFDEF_ACCESSCONF_FILE="${CONF}" \
        SELFDEF_ACCESSCONF_D="${ACCESSD}" \
        bash "${WD}"
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (whitespace tolerance: '+ : backdoor : ALL' with extra spaces still triggers alert)" {
    # Attacker may use multi-spaces to evade naive grep. The access.conf
    # format is ' : '-separated; lock that the parser is tolerant.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '+    :    backdoor    :    ALL\n- : ALL : ALL\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (multi-broad-permit detection: 3+ broad permits all surface in suspicious_sample)" {
    # An attacker may stack multiple backdoor accounts. All MUST
    # surface in the suspicious sample (operator triage payload).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '+ : root : LOCAL\n+ : bd1 : ALL\n+ : bd2 : ALL\n+ : bd3 : ALL\n- : ALL : ALL\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
    # At least one of the backdoor accounts appears in the sample.
    cap | grep -qE 'bd[1-3]'
}

@test "INVARIANT (auto-trust applies to broad permits too: alert fires for THIS run, baseline catches up on next)" {
    # access-conf-watchdog is auto-trust per the existing test —
    # this lock specifically covers broad-permit-alert variant:
    # operator deliberately adds a broad permit (e.g. for new
    # remote-admin service); alert fires for THIS run, but baseline
    # refreshes so next run reports intact.
    seed_benign
    run_wd
    printf '+ : root : LOCAL\n+ : ops-admin : ALL\n- : ALL : ALL\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    cap | grep -q '"severity":"alert"'
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # baseline refreshed
    cap | grep -q '"event":"access_conf_intact"'
}

@test "INVARIANT (severity precedence: broad-permit + benign-change in same scan → alert wins over warn)" {
    # When a scan surfaces BOTH a broad-permit add (alert) AND a
    # benign rule change (warn), severity must be alert. Locks
    # consolidation discipline. Sister to other watchdogs'
    # severity-precedence INVARIANTs (sudoers-integrity, dns-
    # resolver, file-capabilities, ld-so-conf, kernel-usermode-
    # helper, ssh-authkeys, sysctl-hardening).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '+ : root : LOCAL\n+ : backdoor : ALL\n+ : admins : 192.168.1.0/24\n- : ALL : ALL\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"access_conf_broad_permit"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (pre-existing broad permit: baseline_initial fires alert at install-time)" {
    # Sister to every other watchdog pre-existing-broad-condition
    # baseline_initial INVARIANT across the brain. The install-time-
    # vet contract: if /etc/security/access.conf ALREADY carries a
    # broad permit ('+ : backdoor : ALL') when selfdef first installs
    # the watchdog, the first run MUST raise alert (or at least warn)
    # — not silently baseline a broken security posture. Closes the
    # install-time-vet axis on the access-conf permit surveillance
    # surface (T1098 — Account Manipulation via broad-permit
    # backdoor account).
    printf '+ : root : LOCAL\n+ : pre-existing-backdoor : ALL\n- : ALL : ALL\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named broad-permit user surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker adds a broad-
    # permit (+) rule with a distinctively-named user, the user
    # name MUST surface in the JSON sample so operator dashboard
    # routes triage to the right path — operators MUST be able to
    # tell WHICH backdoor account got added without scrolling
    # through grep history. Locks the new-rule-discovered
    # operator-visibility contract on the access-conf permit
    # surveillance surface (T1098 — Account Manipulation via
    # broad-permit backdoor account).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '+ : root : LOCAL\n+ : distinctive-attacker-account : ALL\n- : ALL : ALL\n' > "${CONF}"
    run_wd
    cap | grep -q 'distinctive-attacker-account'
}

@test "INVARIANT (multi-broad-permit: 3 broad permits in one delta scan → all surface in suspicious_sample; consolidation discipline)" {
    # Sister to many other watchdog multi-item single-alert
    # consolidation INVARIANTs across the brain. When an
    # attacker adds multiple broad-permit users at once (mass-
    # backdoor sweep), all MUST surface in the suspicious_sample
    # field so operator dashboard sees the full attacker payload
    # in one record. Locks the consolidation contract on the
    # access-conf permit surveillance surface — multiple T1098
    # account-manipulation grants in one event.
    seed_benign
    run_wd
    printf '+ : root : LOCAL\n+ : backdoor1 : ALL\n+ : backdoor2 : ALL\n+ : backdoor3 : ALL\n- : ALL : ALL\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"added":[3-9]'
    cap | grep -q 'backdoor1\|backdoor2\|backdoor3'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger INVARIANTs.
    # selfdef-access-conf tag must fire EXACTLY ONCE per scan
    # regardless of how many broad-permit additions surface.
    # Lock consolidation discipline on T1136/T1098 access-grant
    # surveillance surface.
    seed_benign
    run_wd
    printf '+ : root : LOCAL\n+ : evil1 : ALL\n+ : evil2 : ALL\n+ : evil3 : ALL\n- : ALL : ALL\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-access-conf -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (baseline re-establish on operator out-of-band deletion: missing baseline re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs.
    # State-resilience on T1136/T1098 access-grant surveillance.
    seed_benign
    run_wd                                              # establishes baseline
    [ -f "${BASELINE}" ]
    rm -f "${BASELINE}"                                  # operator wipe
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # must re-establish
    [ -f "${BASELINE}" ]
    cap | grep -qE '"event":"baseline_initial"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on access-conf surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The access-conf-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1136/T1098 PAM access-grant surveillance
    # alert. Locks parser contract on the /etc/security/access.
    # conf broad-permit detection surface.
    seed_benign
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    printf '+ : root : LOCAL\n+ : evil-backdoor : ALL\n- : ALL : ALL\n' > "${CONF}"
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (baseline file is chmod 0600 — confidentiality of access-conf inventory)" {
    # Sister to brain-wide baseline-chmod-0600 confidentiality
    # INVARIANTs across L2 surveillance suites. The access-conf-
    # watchdog baseline TSV contains the inventory of PAM
    # access.conf user-grant tuples which discloses operator-
    # allowed login-paths to any user able to read the file.
    # Mode 0600 (root-only) is the canonical confidentiality
    # contract — mode 0644 would expose the login-grant
    # whitelist enabling attacker to enumerate which user
    # identities are trusted for credential-grab. Locks file-
    # mode confidentiality on the access-conf surveillance
    # substrate.
    seed_benign
    run_wd
    [ -f "${BASELINE}" ]
    mode="$(stat -c '%a' "${BASELINE}")"
    [ "${mode}" = "600" ] || [ "${mode}" = "640" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # access-conf-watchdog runs ON the timer's scheduled fire —
    # diffs /etc/security/access.conf against baseline, emits a
    # verdict on broad-permit additions (pam_access policy
    # widening), then exits. Type=simple would break timer
    # OnUnitActiveSec semantics. Locks oneshot-probe contract on
    # the access-conf-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/access-conf-watchdog/systemd/selfdef-access-conf.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. access-conf-watchdog manifest declares install +
    # profile gating the resolver enforces; malformed manifest
    # wedges the pam_access policy delta scanner baseline.
    # Python's tomllib is the canonical parser. Locks anti-
    # malformed-manifest on the access-conf-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/access-conf-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'access-conf-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (access-conf-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The access-conf-watchdog libexec uses set -u (and NOT set -e) by
    # design: watchdog probes WANT to continue scanning even
    # when individual checks fail (rather than abort-on-first-
    # error like installers), so they emit a complete verdict
    # at the end. But set -u remains essential — it catches
    # typo'd env-var references ($SELFDEF_FOO_BASELINE vs
    # $SELFDEF_FOO_BASLINE) before they propagate as silent
    # empty-string into baseline-path operations. A regression
    # dropping set -u would let a typo'd var name produce a
    # silent baseline-rewrite to /. Locks set -u discipline on
    # the access-conf-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/access-conf-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (access-conf-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
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
    # SDD-062 logger-tag routing discipline on the access-conf-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/access-conf-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (access-conf-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # The access-conf-watchdog timer unit MUST declare RandomizedDelaySec=
    # so fleet hosts don't all fire at the exact same minute
    # (thundering-herd that overwhelms downstream
    # syslog/journald aggregators). Locks anti-thundering-herd
    # cadence discipline on the access-conf-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/access-conf-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (access-conf-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Persistent=true tells systemd to fire the timer ON BOOT
    # if it was missed during downtime — without it, a host
    # that boots after the scheduled fire would silently skip
    # the cycle, leaving a forensics gap. Locks Persistent=
    # discipline on the access-conf-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/access-conf-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (access-conf-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # The .timer file MUST declare Unit=<companion>.service so
    # systemd knows which .service to fire on timer-elapse. By
    # default systemd matches timer-name to service-name, but
    # explicit Unit= is required when names differ + makes the
    # binding self-documenting. A regression dropping Unit= +
    # renaming either file would silently break the link.
    # Locks the timer-to-service binding discipline on the
    # access-conf-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/access-conf-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (access-conf-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. The .service file MUST declare ExecStart=<path-
    # to-libexec.sh> so systemd knows what to run. The libexec
    # script must EXIST at the declared path. A regression that
    # renamed the libexec script without updating ExecStart
    # would surface as service-start failure rather than a
    # silent regression. Locks the service-to-libexec binding
    # discipline on the access-conf-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/access-conf-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (access-conf-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # The access-conf-watchdog probe is Type=oneshot — it RUNS, emits a
    # verdict, and EXITS. Restart=always on a oneshot would
    # cause systemd to immediately re-fire the probe in a
    # tight loop, swamping the dashboard with redundant
    # records. A regression that added Restart=always would
    # produce a runaway-probe footgun. Locks the anti-restart-
    # storm discipline on the access-conf-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/access-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (access-conf-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. The Description= directive surfaces in
    # `systemctl status` output + journalctl unit-filter
    # labels. A unit with no Description is opaque to
    # operators triaging service activity. Locks the
    # Description-present discipline on the access-conf-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/access-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (access-conf-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the access-conf-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/access-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (access-conf-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the access-conf-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/access-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}
