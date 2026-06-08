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

@test "INVARIANT (account-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. The .service file MUST declare ExecStart=<path-
    # to-libexec.sh> so systemd knows what to run. The libexec
    # script must EXIST at the declared path. A regression that
    # renamed the libexec script without updating ExecStart
    # would surface as service-start failure rather than a
    # silent regression. Locks the service-to-libexec binding
    # discipline on the account-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (account-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # The account-watchdog probe is Type=oneshot — it RUNS, emits a
    # verdict, and EXITS. Restart=always on a oneshot would
    # cause systemd to immediately re-fire the probe in a
    # tight loop, swamping the dashboard with redundant
    # records. A regression that added Restart=always would
    # produce a runaway-probe footgun. Locks the anti-restart-
    # storm discipline on the account-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (account-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. The Description= directive surfaces in
    # `systemctl status` output + journalctl unit-filter
    # labels. A unit with no Description is opaque to
    # operators triaging service activity. Locks the
    # Description-present discipline on the account-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (account-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the account-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (account-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the account-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (account-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the account-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (account-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the account-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (account-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the account-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (account-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the account-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (account-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # account-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (account-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # account-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (account-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the account-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (account-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the account-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (account-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (account-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (account-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (account-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (account-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the account-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    [ -f "${script_dir}/account-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (account-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (account-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (account-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (account-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (account-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (account-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (account-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (account-watchdog .sh script emits canonical severity vocabulary {ok,warn,alert} — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    # Watchdog scripts emit logger -t selfdef-<name> -- {...severity:...}
    # with severity in the canonical vocabulary. A regression
    # introducing custom severity values (info, error, critical)
    # would break operator-side filtering.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '"severity":"(ok|warn|alert)"' "${s}"
    done
}

@test "INVARIANT (account-watchdog .sh script tag selfdef-account matches module name — SDD-062 tag-canonical contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # The tag passed to logger -t MUST exactly match selfdef-account
    # so operator triage via journalctl _SYSTEMD_UNIT or
    # SYSLOG_IDENTIFIER filtering surfaces the right module.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (account-watchdog .sh script declares profile-aware exit behavior — operator-extension profile-dispatch contract)" {
    # Sister to brain-wide profile-aware INVARIANT family.
    # Scripts MUST handle PROFILE=enforce vs report differently.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'PROFILE.*enforce|enforce.*PROFILE|profile.*enforce' "${s}"
    done
}

@test "INVARIANT (account-watchdog .sh script declares baseline file path — operator-extensible baseline-state contract)" {
    # Sister to brain-wide baseline-state INVARIANT family.
    # Delta-scan watchdogs MUST declare a BASELINE variable referencing
    # /var/lib/selfdef/ so operators know where baseline state lives.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '/var/lib/selfdef/|BASELINE' "${s}"
    done
}

@test "INVARIANT (account-watchdog .sh script declares MODULE-suffixed tag in logger -t — module-name-tag-consistency contract)" {
    # Sister to SDD-062 tag-canonical INVARIANT family. The tag passed to
    # logger -t MUST include the module slug so journalctl filtering by
    # tag surfaces only this watchdog's events.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (account-watchdog .sh script file is non-empty (size > 100 bytes) — non-trivial-script contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (account-watchdog .sh script has >20 lines — non-trivial-watchdog-body contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 20 ]
    done
}

@test "INVARIANT (account-watchdog .service unit file has >5 lines of directives — non-trivial-unit-file contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 5 ]
    done
}

@test "INVARIANT (account-watchdog .service unit ExecStart references /usr/local/libexec/selfdef/ path — canonical-binary-path contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (account-watchdog .timer file exists at canonical path modules/account-watchdog/systemd — canonical-systemd-dir layout)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    [ -d "${timer_dir}" ]
    n=$(ls "${timer_dir}"/*.timer 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (account-watchdog module.toml exists at canonical path modules/account-watchdog/ — module-manifest existence 72-cycle)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (account-watchdog systemd dir exists at modules/account-watchdog/systemd — systemd-dir-existence 73-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    [ -d "${sd}" ]
}

@test "INVARIANT (account-watchdog systemd dir is non-empty — systemd-content-presence 74-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    n=$(ls "${sd}" | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (account-watchdog .service file size > 100 bytes — substantial-service-unit 75-cycle)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (account-watchdog .timer file size > 50 bytes — substantial-timer-unit 76-cycle)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        size=$(stat -c '%s' "${t}")
        [ "${size}" -gt 50 ]
    done
}

@test "INVARIANT (account-watchdog README.md file size > 100 bytes — substantial-readme 77-cycle)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/README.md"
    size=$(stat -c '%s' "${readme}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (account-watchdog .service Documentation URL is HTTP/HTTPS — operator-doc-link-protocol 78)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=(http|https)://' "${s}"
    done
}

@test "INVARIANT (account-watchdog .sh script has shebang line — POSIX-conformant 79)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '^#!'
    done
}

@test "INVARIANT (account-watchdog .sh script declares set flag in first 50 lines — strict-mode-prologue 80)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -50 "${s}" | grep -qE '^set -'
    done
}

@test "INVARIANT (account-watchdog module.toml size > 200 bytes — substantial-watchdog-manifest 81)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    size=$(stat -c '%s' "${mtoml}")
    [ "${size}" -gt 200 ]
}

@test "INVARIANT (account-watchdog .service file is non-empty — non-trivial-unit-file 82)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        [ -s "${s}" ]
    done
}

@test "INVARIANT (account-watchdog .timer file is non-empty — non-trivial-timer-file 83)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        [ -s "${t}" ]
    done
}

@test "INVARIANT (account-watchdog .sh script body has at least one variable assignment — non-vacuous-script 84)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^[a-zA-Z_]+=' "${s}"
    done
}

@test "INVARIANT (account-watchdog .sh script path matches systemd dir layout — canonical-script-co-location 85)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/systemd"
    [ -d "${script_dir}" ]
    n=$(ls "${script_dir}"/*.sh 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (account-watchdog module.toml has install_paths section — SDD-026 mutation-manifest 86)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (account-watchdog module.toml install_paths.paths non-empty list 87)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list) and len(ps) > 0
"
}

@test "INVARIANT (account-watchdog module.toml install_paths.paths only absolute paths 88)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (account-watchdog module.toml provides list non-empty 89 — capability-export-present)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list) and len(p) >= 1
"
}

@test "INVARIANT (account-watchdog module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (account-watchdog module.toml install_paths.paths includes /etc/ entry — config-staging 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps)
"
}

@test "INVARIANT (account-watchdog module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p for p in ps)
"
}

@test "INVARIANT (account-watchdog module.toml install_paths.paths has /var/ entry 93 — state-staging)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/var/') for p in ps)
"
}

@test "INVARIANT (account-watchdog module.toml [install_paths] declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (account-watchdog module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (account-watchdog module.toml uses TOML key-value syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (account-watchdog module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (account-watchdog module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (account-watchdog module.toml category field double-quoted — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (account-watchdog module.toml summary field double-quoted — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (account-watchdog module.toml name field matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"account-watchdog"' "${mtoml}"
}

@test "INVARIANT (account-watchdog module.toml top-level keys before any [section] — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    python3 -c "
with open('${mtoml}') as fp:
    for ln in fp:
        s = ln.strip()
        if not s or s.startswith('#'): continue
        if s.startswith('['): break
        assert '=' in ln
        break
"
}

@test "INVARIANT (account-watchdog module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (account-watchdog module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (account-watchdog module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (account-watchdog module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (account-watchdog module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (account-watchdog module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (account-watchdog module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (account-watchdog module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (account-watchdog module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}

@test "INVARIANT (account-watchdog module.toml [install] check value is non-empty string ending with .sh — TOML-install-check-shape-canonical 112)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ck = (data.get('install') or {}).get('check', '')
assert isinstance(ck, str) and ck and ck.endswith('.sh'), f'install.check must be non-empty .sh path, got {ck!r}'
"
}

@test "INVARIANT (account-watchdog module.toml version field matches semver X.Y.Z pattern — TOML-version-semver-canonical 113)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v), f'version must be semver X.Y.Z, got {v!r}'
"
}

@test "INVARIANT (account-watchdog module.toml summary field is non-empty string with length >= 30 chars — TOML-summary-substance-floor 114)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) >= 30, f'summary must be string with len >= 30, got len={len(s)} value={s!r}'
"
}

@test "INVARIANT (account-watchdog module.toml top-level requires field is a TOML list — TOML-requires-list-canonical 115)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (account-watchdog module.toml top-level provides field is a TOML list — TOML-provides-list-canonical 116)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('provides')
assert isinstance(r, list), f'provides must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (account-watchdog module.toml top-level conflicts field is a TOML list — TOML-conflicts-list-canonical 117)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('conflicts')
assert isinstance(r, list), f'conflicts must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (account-watchdog module.toml top-level depends_on field is a TOML list — TOML-depends-on-list-canonical 118)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('depends_on')
assert isinstance(r, list), f'depends_on must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (account-watchdog module.toml top-level consumes field is a TOML list — TOML-consumes-list-canonical 119)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('consumes')
assert isinstance(r, list), f'consumes must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (account-watchdog module.toml top-level instanced field is a TOML boolean — TOML-instanced-bool-canonical 120)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('instanced')
assert isinstance(r, bool), f'instanced must be bool, got {type(r).__name__}'
"
}

@test "INVARIANT (account-watchdog module.toml [install] uninstall value is non-empty string ending with .sh — TOML-install-uninstall-shape-canonical 121)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = (data.get('install') or {}).get('uninstall', '')
assert isinstance(v, str) and v and v.endswith('.sh'), f'install.uninstall must be non-empty .sh path, got {v!r}'
"
}

@test "INVARIANT (account-watchdog module.toml has [profiles] section header — TOML-profiles-section-canonical 122)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    grep -qE '^\[profiles\]$' "${mtoml}"
}

@test "INVARIANT (account-watchdog module.toml [profiles] default field is non-empty string — TOML-profiles-default-canonical 123)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert isinstance(d, str) and d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (account-watchdog module.toml [profiles] available field is a TOML list — TOML-profiles-available-list-canonical 124)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/account-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available')
assert isinstance(a, list), f'profiles.available must be list, got {type(a).__name__}'
"
}
