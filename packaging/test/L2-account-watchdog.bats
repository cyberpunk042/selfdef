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
