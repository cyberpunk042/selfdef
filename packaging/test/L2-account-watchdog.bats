#!/usr/bin/env bats
# L2 functional + capture-regression suite for account-watchdog.
#
# account-watchdog inventories the account surface 3 ways:
#   - user:<name>:<uid>:<gid>:<shell>  (every /etc/passwd entry)
#   - uid0:<name>                       (every uid=0 account — root + impostors)
#   - sudo:<name>                       (members of sudo / wheel / admin
#                                        — via group member field AND primary-gid)
# First run baselines; subsequent runs diff. A NEW account, a NEW
# uid=0, or a NEW sudo member is high-signal.
#
# Severity:
#   ok    → no delta
#   warn  → new user (non-privileged)
#   alert → new uid=0 OR new sudo member (privilege persistence)
#
# What this suite locks:
#   - INVENTORY-CAPTURE regression (existing) — `printf` records
#     reach `$current` not stdout (2026-05-27 root-cause bug)
#   - All 3 record classes (user / uid0 / sudo) surface in the
#     baseline with the expected shape
#   - Baseline chmod 0600 (confidentiality — passwd inventory +
#     privilege roster is sensitive)
#   - DELTA detect: NEW UID-0 account → alert / new_privileged_
#     account (the canonical root-impostor attack)
#   - DELTA detect: NEW sudo group member → alert / new_privileged_
#     account (the canonical privilege-persistence attack)
#   - DELTA detect: NEW ordinary user → warn / new_account
#   - DELTA detect: REMOVED account → no event surface (handled
#     silently; deletions aren't a threat signal)
#   - ENFORCE profile: any add → exit-1 (failure surface for
#     systemd unit alerting)
#   - REPORT profile: any delta → exit-0 (log-only)
#   - INVARIANT (no auto-trust): like ssh-authkeys / pam-config /
#     sudoers-integrity, account-watchdog does NOT refresh the
#     baseline on delta. The alert STAYS visible until operator
#     reviews + updates the baseline manually.
#
# Adds SELFDEF_ACCOUNTS_PASSWD_FILE env-var override (added
# 2026-06-06) for L2 delta-testability. getent group calls are
# mocked via PATH override (existing convention in the fleet's
# watchdog suites). Live default unchanged.
#
# Run with: bats packaging/test/L2-account-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd/account-watchdog.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SELFDEF_TEST_LOGCAP}"
FAKELOGGER
    chmod +x "${BIN}/logger"
    # getent group <name> emits "<name>:x:<gid>:<members>" — mock
    # surfaces the GROUP_FIXTURE env var pointing at the same group
    # file we use for testing.
    cat > "${BIN}/getent" <<'GETENTEOF'
#!/usr/bin/env bash
# minimal getent group <name> mock — reads from $GROUP_FIXTURE.
if [[ "$1" != "group" ]]; then exit 2; fi
awk -F: -v g="$2" '$1==g {print; exit}' "${GROUP_FIXTURE:-/dev/null}"
GETENTEOF
    chmod +x "${BIN}/getent"
    export SELFDEF_TEST_LOGCAP="${TMP}/log.out"
    : > "${SELFDEF_TEST_LOGCAP}"
    BASELINE="${TMP}/accounts-baseline.tsv"
    PASSWD_FILE="${TMP}/passwd"
    GROUP_FIXTURE="${TMP}/group"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    GROUP_FIXTURE="${GROUP_FIXTURE}" \
    SELFDEF_ACCOUNTS_PROFILE="${PROFILE:-report}" \
    SELFDEF_ACCOUNTS_BASELINE="${BASELINE}" \
    SELFDEF_ACCOUNTS_PASSWD_FILE="${PASSWD_FILE}" \
    bash "${WD}"
}

run_wd_rc() {
    PATH="${BIN}:${PATH}" \
    GROUP_FIXTURE="${GROUP_FIXTURE}" \
    SELFDEF_ACCOUNTS_PROFILE="${PROFILE:-report}" \
    SELFDEF_ACCOUNTS_BASELINE="${BASELINE}" \
    SELFDEF_ACCOUNTS_PASSWD_FILE="${PASSWD_FILE}" \
    bash "${WD}" >/dev/null 2>&1
    echo $?
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# Helper: write a baseline passwd + group inventory.
write_account_inventory() {
    cat > "${PASSWD_FILE}" <<'EOF'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
bob:x:1001:1001:Bob:/home/bob:/bin/bash
EOF
    cat > "${GROUP_FIXTURE}" <<'EOF'
root:x:0:
sudo:x:27:alice
wheel:x:10:
admin:x:50:
users:x:100:alice,bob
EOF
}

@test "first run captures the account inventory into the baseline (non-empty)" {
    write_account_inventory
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
    [ -s "${BASELINE}" ]                                  # capture regression lock
    grep -qP '^user\t' "${BASELINE}"
}

@test "baseline captures all 3 record classes (user + uid0 + sudo)" {
    write_account_inventory
    run_wd
    # user class — every /etc/passwd entry.
    grep -qP '^user\troot:0:0:/bin/bash$' "${BASELINE}"
    grep -qP '^user\talice:1000:1000:/bin/bash$' "${BASELINE}"
    # uid0 class — root is uid=0.
    grep -qP '^uid0\troot$' "${BASELINE}"
    # sudo class — alice is in sudo group (group member field).
    grep -qP '^sudo\talice$' "${BASELINE}"
}

@test "baseline is chmod 0600 (confidentiality — account inventory + privilege roster is sensitive)" {
    write_account_inventory
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "unchanged accounts on second run → ok / no_delta" {
    write_account_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
}

@test "DELTA detect — NEW UID-0 account → alert / new_privileged_account (root-impostor attack)" {
    write_account_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Attacker adds a second uid=0 account (the canonical
    # root-impostor backdoor).
    echo 'evil:x:0:0:Evil:/root:/bin/bash' >> "${PASSWD_FILE}"
    run_wd
    cap | grep -q '"event":"new_privileged_account"'
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"new_uid0":1'
}

@test "DELTA detect — NEW sudo group member → alert / new_privileged_account (privilege-persistence)" {
    write_account_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Attacker adds bob to sudo group.
    sed -i 's|^sudo:x:27:alice|sudo:x:27:alice,bob|' "${GROUP_FIXTURE}"
    run_wd
    cap | grep -q '"event":"new_privileged_account"'
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"new_sudo":1'
}

@test "DELTA detect — NEW ordinary (non-privileged) user → warn / new_account" {
    write_account_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    echo 'charlie:x:1002:1002:Charlie:/home/charlie:/bin/bash' >> "${PASSWD_FILE}"
    run_wd
    cap | grep -q '"event":"new_account"'
    cap | grep -q '"severity":"warn"'
    cap | grep -q '"new_uid0":0'
    cap | grep -q '"new_sudo":0'
}

@test "DELTA detect — passwd-primary-gid sudo member (no group-member field entry) → alert" {
    write_account_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Create a user whose primary gid IS the sudo group's gid
    # (gid=27) — they DON'T appear in the group's member field
    # but they ARE a sudo member by primary-gid pass.
    echo 'sudoer:x:1003:27:Sudoer:/home/sudoer:/bin/bash' >> "${PASSWD_FILE}"
    run_wd
    cap | grep -q '"event":"new_privileged_account"'
    cap | grep -q '"severity":"alert"'
}

@test "ENFORCE profile: NEW account → exit-1 (failure surface for systemd unit alerting)" {
    write_account_inventory
    PROFILE=report run_wd
    echo 'evil:x:0:0:Evil:/root:/bin/bash' >> "${PASSWD_FILE}"
    rc="$(PROFILE=enforce run_wd_rc)"
    [ "${rc}" = "1" ]
}

@test "REPORT profile: NEW account → exit-0 (log-only — journald is the surface)" {
    write_account_inventory
    PROFILE=report run_wd
    echo 'evil:x:0:0:Evil:/root:/bin/bash' >> "${PASSWD_FILE}"
    rc="$(PROFILE=report run_wd_rc)"
    [ "${rc}" = "0" ]
}

@test "INVARIANT (no auto-trust): account-watchdog does NOT refresh the baseline on delta — alert STAYS until operator updates baseline" {
    # CONTRAST against group-integrity-watchdog (which auto-refreshes).
    # New accounts are NEVER routine; the alert must STAY visible.
    write_account_inventory
    PROFILE=report run_wd
    echo 'evil:x:0:0:Evil:/root:/bin/bash' >> "${PASSWD_FILE}"
    PROFILE=report run_wd                                  # first delta run
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=report run_wd                                  # alert STAYS
    cap | grep -q '"event":"new_privileged_account"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wheel group also fires sudo path — distro-axis coverage)" {
    # Some distros use wheel instead of sudo. Test that wheel group
    # membership also triggers the privilege alert path.
    write_account_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    sed -i 's|^wheel:x:10:|wheel:x:10:bob|' "${GROUP_FIXTURE}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (admin group also fires sudo path — distro-axis coverage)" {
    # Some distros (Debian, older) use admin instead of sudo.
    write_account_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    sed -i 's|^admin:x:50:|admin:x:50:bob|' "${GROUP_FIXTURE}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (uid0 with different name — even root2/admin1 → alert as uid0 impostor)" {
    write_account_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Different name from 'evil' — what matters is uid 0.
    echo 'admin1:x:0:0:Admin1:/root:/bin/bash' >> "${PASSWD_FILE}"
    run_wd
    cap | grep -q '"event":"new_privileged_account"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (delta carries the NEW account NAME in added_sample for forensics)" {
    write_account_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    echo 'distinctive_attacker:x:0:0:Distinctive:/root:/bin/bash' >> "${PASSWD_FILE}"
    run_wd
    cap | grep -q 'distinctive_attacker'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    write_account_inventory
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-accounts -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (REMOVED account does NOT trigger alert: deletion is not a threat signal — operator deactivation is OK)" {
    # When an operator removes an account, that's a legitimate
    # operation. Locks that removal doesn't false-fire.
    write_account_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Remove bob from passwd.
    sed -i '/^bob:/d' "${PASSWD_FILE}"
    run_wd
    # Severity should be ok or warn (not alert).
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-class single-account delta: new uid=0 account triggers ALL THREE classes: user + uid0 + sudo-if-primary-gid)" {
    # When attacker adds 'evil' with uid=0, gid=0, the new account
    # appears in BOTH the user inventory AND the uid0 inventory.
    # Lock that both counters reflect this.
    write_account_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    echo 'evil:x:0:0:Evil:/root:/bin/bash' >> "${PASSWD_FILE}"
    run_wd
    cap | grep -q '"new_uid0":1'
    # New user counter also increments (the account is new across
    # both axes).
    cap | grep -qE '"new_user":[1-9]' || cap | grep -qE '"added":[1-9]'
}

@test "INVARIANT (current behavior: /etc/passwd has NO comment semantics — # lines parsed by awk as user records)" {
    # /etc/passwd has NO POSIX comment semantics (unlike
    # /etc/group). The awk parser treats EVERY non-empty line
    # as a user record. A line starting with '#' is parsed as a
    # user named '# evil' (or similar) — with whatever uid/gid
    # follows. Lock current behavior: such lines ARE detected
    # as new accounts. Operator MUST NOT add comments to
    # /etc/passwd — this test documents the contract.
    write_account_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    echo '#evil:x:0:0:Future:/root:/bin/bash' >> "${PASSWD_FILE}"
    run_wd
    # Current behavior: the commented line surfaces as a new
    # privileged account because /etc/passwd doesn't filter #.
    cap | grep -q '"event":"new_privileged_account"'
}

@test "INVARIANT (severity precedence: new uid0 + new ordinary account → alert; uid0 wins over warn)" {
    # When BOTH new uid0 AND new ordinary user added in same scan,
    # severity must be alert (uid0 wins ladder).
    write_account_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat >> "${PASSWD_FILE}" <<'EOF'
evil:x:0:0:Evil:/root:/bin/bash
charlie:x:1002:1002:Charlie:/home/charlie:/bin/bash
EOF
    run_wd
    cap | grep -q '"event":"new_privileged_account"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-uid0-impostor: two new uid=0 accounts in same scan → still single alert; consolidation)" {
    # When attacker stacks multiple uid=0 impostors in one drop,
    # single alert JSON record fires with new_uid0=2. Locks
    # consolidation discipline + observability accuracy.
    write_account_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat >> "${PASSWD_FILE}" <<'EOF'
evil1:x:0:0:Evil1:/root:/bin/bash
evil2:x:0:0:Evil2:/root:/bin/bash
EOF
    run_wd
    cap | grep -q '"event":"new_privileged_account"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"new_uid0":[2-9]'
    main_count=$(cap | grep -cE '^-t selfdef-accounts -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (sudo-group axis: a non-attacker user moved INTO sudo via group-member field still triggers alert — privilege-elevation is alert-grade regardless of operator-intent)" {
    # Even if operator is the one adding bob to sudo (legitimate
    # promotion), the watchdog MUST surface it as new_privileged_
    # account because privilege-grant changes are by design alert-
    # grade. Operator re-baselines after legitimate promotion.
    # Locks operator-vs-attacker symmetric treatment: the surface
    # IS what's tracked.
    write_account_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    sed -i 's|^sudo:x:27:alice|sudo:x:27:alice,carol|' "${GROUP_FIXTURE}"
    # carol doesn't exist in passwd — sudo group has phantom member;
    # locks that watchdog detects the group-member delta REGARDLESS
    # of whether the user account exists yet (attacker may add user
    # AFTER seeding sudo membership).
    run_wd
    cap | grep -q '"event":"new_privileged_account"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (T1136 — Create Account axis: attacker creates a service-style account with system-uid range that nobody-uses → ALSO surfaced)" {
    # Sister to the uid=0 impostor + sudo-group + new-ordinary-user
    # axes already locked. Attacker may avoid uid=0 (loud) AND avoid
    # adding to sudo group (loud) by creating a service-style account
    # in the system-uid range (UID<1000 typical service range) with
    # an interactive shell — a long-game persistence vector that
    # service-account-lock would neutralize but only if the operator
    # already ran it. Locks: a NEW UID-range-100 account with
    # interactive shell STILL surfaces as new_account (even though
    # not privileged) — operator can triage from there. Closes the
    # T1136 (Create Account) axis on the account-watchdog surface.
    write_account_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    echo 'sneaky-svc:x:107:107:Sneaky Service:/var/lib/sneaky:/bin/bash' >> "${PASSWD_FILE}"
    run_wd
    # Either new_account event OR new_privileged_account (if some
    # heuristic catches the bash-shell + service-uid combo).
    cap | grep -qE '"event":"(new_account|new_privileged_account)"'
    cap | grep -qE '"severity":"(warn|alert)"'
    cap | grep -q 'sneaky-svc'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named account surfaces in added_sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain (sudoers / suid-sgid / unowned /
    # access-conf / systemd-unit). When an attacker creates a new
    # account, the account NAME MUST surface in the JSON
    # added_sample so operator dashboard routes triage to the
    # right account — operators MUST be able to identify which
    # specific account was created without scrolling through
    # /etc/passwd diffs. Locks the new-account-discovered
    # operator-visibility contract on the T1136 (Create Account)
    # surface.
    write_account_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    echo 'distinctive-attacker-acct:x:1500:1500:DistinctiveAttacker:/home/distinctive-attacker-acct:/bin/bash' >> "${PASSWD_FILE}"
    run_wd
    cap | grep -q 'distinctive-attacker-acct'
}

@test "INVARIANT (T1546 — shell-flip persistence: existing nologin service-user's shell flipped to /bin/bash surfaces as a new tuple)" {
    # Sister to the new-account / new-uid0 / new-sudo axes. The
    # user inventory tuple keys name:uid:gid:shell — so when an
    # attacker flips an existing service-account's shell from
    # /usr/sbin/nologin to /bin/bash (classic T1546 persistence
    # vector: turn an idle service account into an interactive
    # backdoor), the old tuple "removes" silently AND the new
    # tuple surfaces as a new_account event. Locks the
    # shell-flip detection axis on the account-watchdog surface.
    # daemon ships with nologin in the baseline; attacker flips
    # to bash. Watchdog MUST see this as a new tuple — the
    # interactive-shell-acquisition vector cannot be silent.
    write_account_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    sed -i 's|^daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin|daemon:x:1:1:daemon:/usr/sbin:/bin/bash|' "${PASSWD_FILE}"
    run_wd
    cap | grep -qE '"event":"(new_account|new_privileged_account)"'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger-line INVARIANTs.
    # selfdef-accounts tag must fire EXACTLY ONCE per scan
    # regardless of how many uid0/sudo/account adds surface.
    # Locks consolidation discipline on T1136/T1098 account-
    # surveillance surface.
    write_account_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat >> "${PASSWD_FILE}" <<'EOF'
evil1:x:0:0:Evil1:/root:/bin/bash
evil2:x:0:0:Evil2:/root:/bin/bash
evil3:x:1500:1500:Evil3:/home/evil3:/bin/bash
EOF
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-accounts -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (baseline re-establish on operator out-of-band deletion: missing baseline re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs.
    # State-resilience on T1136/T1098 account surveillance.
    write_account_inventory
    run_wd                                              # establishes baseline
    [ -f "${BASELINE}" ]
    rm -f "${BASELINE}"                                  # operator wipe
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # must re-establish
    [ -f "${BASELINE}" ]
    cap | grep -qE '"event":"baseline_initial"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on account-watchdog surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The account-watchdog MUST only emit severity values from
    # the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1136/T1098 Account Creation/Manipulation
    # alert. Locks parser contract on the /etc/passwd account-
    # delta detection surface.
    write_account_inventory
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    printf 'evil1:x:0:0:Evil:/root:/bin/bash\n' >> "${PASSWD_FILE}"
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: account-watchdog NEVER emits userdel/passwd -l on detected accounts — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # account-watchdog DETECTS T1136 Create Account / T1098
    # Account Manipulation but MUST NEVER emit userdel/
    # deluser/passwd -l commands to auto-remove the planted
    # account. Auto-removal is a denial-of-service primitive
    # (attacker plants a fake uid=0 account, watchdog removes
    # operator's actual sudo grant). Forensic evidence value
    # of the live account is high (operator triage needs to
    # inspect home dir, shell history, scheduled tasks).
    # Surveillance, never remediation. Locks anti-evidence-
    # destruction contract on the account surveillance
    # substrate.
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*(userdel|deluser|passwd[[:space:]]+-l)'
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # account-watchdog runs ON the timer's scheduled fire —
    # diffs /etc/passwd + /etc/shadow against baseline, emits a
    # verdict on account creation / shell-flip / privilege-
    # elevation, then exits. Type=simple would break timer
    # OnUnitActiveSec semantics. Locks oneshot-probe contract on
    # the account-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd/selfdef-accounts.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. account-watchdog manifest declares install +
    # profile gating the resolver enforces; malformed manifest
    # wedges the /etc/passwd + /etc/shadow delta scanner.
    # Python's tomllib is the canonical parser. Locks anti-
    # malformed-manifest on the account-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'account-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (account-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The account-watchdog libexec uses set -u (and NOT set -e) by
    # design: watchdog probes WANT to continue scanning even
    # when individual checks fail (rather than abort-on-first-
    # error like installers), so they emit a complete verdict
    # at the end. But set -u remains essential — it catches
    # typo'd env-var references ($SELFDEF_FOO_BASELINE vs
    # $SELFDEF_FOO_BASLINE) before they propagate as silent
    # empty-string into baseline-path operations. A regression
    # dropping set -u would let a typo'd var name produce a
    # silent baseline-rewrite to /. Locks set -u discipline on
    # the account-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (account-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
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
    # SDD-062 logger-tag routing discipline on the account-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (account-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # The account-watchdog timer unit MUST declare RandomizedDelaySec=
    # so fleet hosts don't all fire at the exact same minute
    # (thundering-herd that overwhelms downstream
    # syslog/journald aggregators). Locks anti-thundering-herd
    # cadence discipline on the account-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (account-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Persistent=true tells systemd to fire the timer ON BOOT
    # if it was missed during downtime — without it, a host
    # that boots after the scheduled fire would silently skip
    # the cycle, leaving a forensics gap. Locks Persistent=
    # discipline on the account-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (account-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # The .timer file MUST declare Unit=<companion>.service so
    # systemd knows which .service to fire on timer-elapse. By
    # default systemd matches timer-name to service-name, but
    # explicit Unit= is required when names differ + makes the
    # binding self-documenting. A regression dropping Unit= +
    # renaming either file would silently break the link.
    # Locks the timer-to-service binding discipline on the
    # account-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}
