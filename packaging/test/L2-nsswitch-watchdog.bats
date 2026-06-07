#!/usr/bin/env bats
# L2 bats functional tests for the nsswitch-watchdog scan script.
#
# /etc/nsswitch.conf maps each identity/name database to ordered lookup
# sources; each source X loads libnss_X.so into every getpwnam/gethostbyname
# caller. A rogue source (`passwd: files evil`) backdoors identity + auth
# resolution host-wide (T1556/T1574). Severity:
#   ok    → no delta
#   warn  → file hash changed / a known source added/reordered
#   alert → an UNKNOWN (non-standard) source on any db, OR a db line removed
#
# Run with: bats packaging/test/L2-nsswitch-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/nsswitch-watchdog/systemd/nsswitch-watchdog.sh"

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
    CONF="${TMP}/nsswitch.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_NSSWITCH_PROFILE="${PROFILE:-report}" \
    SELFDEF_NSSWITCH_BASELINE="${BASELINE}" \
    SELFDEF_NSSWITCH_CONF="${CONF}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf 'passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n' > "${CONF}"
}

@test "benign nsswitch, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged nsswitch on second run → ok / nsswitch_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"nsswitch_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "an unknown (rogue) source on a db → alert / nsswitch_rogue_source" {
    seed_benign
    run_wd
    printf 'passwd: files evil\ngroup: files\nshadow: files\nhosts: files dns\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"nsswitch_rogue_source"'
    cap | grep -q '"severity":"alert"'
}

@test "a database line removed → alert / nsswitch_db_removed" {
    seed_benign
    run_wd
    printf 'passwd: files\nshadow: files\nhosts: files dns\n' > "${CONF}"   # group line gone
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"nsswitch_db_removed"'
    cap | grep -q '"severity":"alert"'
}

@test "a benign known-source addition → warn / nsswitch_changed" {
    seed_benign
    run_wd
    printf 'passwd: files\ngroup: files\nshadow: files\nhosts: files dns myhostname\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"nsswitch_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign nsswitch is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "enforce profile exits non-zero on a rogue source" {
    seed_benign
    run_wd
    printf 'passwd: files evil\ngroup: files\nshadow: files\nhosts: files dns\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — nsswitch inventory enumerates identity-resolution providers)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (known-source acceptance): `sss` (SSSD) on passwd is NOT flagged (LDAP/AD-integrated host)" {
    # SSSD is a canonical legit enterprise-NSS provider. Locks
    # that the KNOWN_NSS allow-list includes it.
    seed_benign
    run_wd
    printf 'passwd: files sss\ngroup: files sss\nshadow: files sss\nhosts: files dns\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(warn|ok)"'              # not alert — sss is known
    ! cap | grep -q '"event":"nsswitch_rogue_source"'
}

@test "INVARIANT (known-source acceptance): `systemd` provider is NOT flagged (machined integration)" {
    seed_benign
    run_wd
    printf 'passwd: files systemd\ngroup: files systemd\nshadow: files\nhosts: files dns\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    ! cap | grep -q '"event":"nsswitch_rogue_source"'
}

@test "INVARIANT (known-source acceptance): `mdns_minimal` provider is NOT flagged (Avahi/Bonjour)" {
    seed_benign
    run_wd
    printf 'passwd: files\ngroup: files\nshadow: files\nhosts: files mdns_minimal dns\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    ! cap | grep -q '"event":"nsswitch_rogue_source"'
}

@test "INVARIANT (rogue: multiple unknown sources on different dbs) → still alert (full-system rogue NSS attack)" {
    # A multi-db rogue NSS attack drops libnss_evil.so AND
    # libnss_backdoor.so on different dbs. Locks that the
    # watchdog catches a multi-db rogue addition (not just a
    # single-db one).
    seed_benign
    run_wd
    printf 'passwd: files evil\ngroup: files backdoor\nshadow: files\nhosts: files dns\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"nsswitch_rogue_source"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (pre-existing rogue): baseline_initial fires alert if nsswitch already has a rogue source at install-time" {
    printf 'passwd: files evil\ngroup: files\nshadow: files\nhosts: files dns\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-nsswitch -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): nsswitch-watchdog does NOT refresh baseline on rogue detection — alert STAYS until operator updates" {
    # Rogue NSS sources are NEVER routine; the alert must persist
    # across runs until operator explicitly re-baselines. Locks
    # against a regression that copies the auto-trust pattern
    # from sister modules.
    seed_benign
    run_wd
    printf 'passwd: files evil\ngroup: files\nshadow: files\nhosts: files dns\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"nsswitch_rogue_source"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented db line is NOT included in rogue-source inventory: # prefix filtered)" {
    # Operator notes about future db sources must not be parsed
    # as actual sources. A commented '# passwd: files evil' must
    # not surface as a rogue source.
    printf 'passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n# notes: discussed evil module\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (whitespace tolerance in db lookup: multi-space-separated sources normalized)" {
    # Operator may write 'passwd:  files  sss' with multiple spaces
    # between tokens. The parser must normalize whitespace.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'passwd:  files  sss\ngroup: files\nshadow: files\nhosts: files dns\n' > "${CONF}"
    run_wd
    # sss is a KNOWN source — even with weird whitespace it must
    # not be treated as rogue.
    ! cap | grep -q '"event":"nsswitch_rogue_source"'
}

@test "INVARIANT (rogue sample format: db:rogue_source — operator triage payload)" {
    # The sample field shape lets operator instantly know WHICH
    # db gained which rogue source.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'passwd: files evil_backdoor\ngroup: files\nshadow: files\nhosts: files dns\n' > "${CONF}"
    run_wd
    cap | grep -q 'passwd'
    cap | grep -q 'evil_backdoor'
}

@test "INVARIANT (known-source acceptance: ldap is NOT flagged — enterprise LDAP-integrated host)" {
    # ldap is a canonical legit enterprise-NSS provider via libnss-ldapd.
    # Locks that the KNOWN_NSS allow-list includes it.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'passwd: files ldap\ngroup: files ldap\nshadow: files ldap\nhosts: files dns\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"event":"nsswitch_rogue_source"'
}

@test "INVARIANT (rogue on hosts db — DNS-resolver hijack — also alerts)" {
    # hosts db is the DNS-resolver provider chain. A rogue source on
    # hosts db is a name-resolution hijack (T1556/T1574).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'passwd: files\ngroup: files\nshadow: files\nhosts: files dns evil_dns_hijack\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"nsswitch_rogue_source"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (rogue on shadow db — credential-store hijack — also alerts)" {
    # shadow db backs the password hash store. A rogue source on shadow
    # backdoors the credential verification path.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'passwd: files\ngroup: files\nshadow: files evil_cred_hijack\nhosts: files dns\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"nsswitch_rogue_source"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (rogue on group db — group-membership hijack — also alerts)" {
    # Sister to rogue-on-passwd + rogue-on-shadow + rogue-on-hosts axes
    # already locked. group db backs the group-membership lookup. A
    # rogue source on group lets an attacker swap in their own libnss_
    # X.so that returns whatever group memberships they choose — direct
    # privesc vector (claim 'root', 'wheel', 'sudo' membership via the
    # rogue NSS provider). T1556/T1574 sister axis on the group-
    # membership resolution chain.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'passwd: files\ngroup: files evil_group_hijack\nshadow: files\nhosts: files dns\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"nsswitch_rogue_source"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (known-source acceptance: sssd is NOT flagged — enterprise SSSD-integrated host)" {
    # Sister to the ldap known-source-acceptance INVARIANT already
    # locked. sssd is a canonical legitimate enterprise-NSS provider
    # via libnss-sss (the SSSD provider for AD/IPA/LDAP-backed
    # identity). Locks that the KNOWN_NSS allow-list includes sssd
    # alongside ldap (operator-friendly false-positive guard for
    # SSSD-integrated hosts).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'passwd: files sss\ngroup: files sss\nshadow: files sss\nhosts: files dns\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"event":"nsswitch_rogue_source"'
}

@test "INVARIANT (DELTA detect — distinctive-attacker-named rogue NSS source surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker adds a
    # distinctively-named NSS module to passwd/group/shadow/
    # hosts (T1556.001 — Modify Authentication Process via
    # NSS module hijack; libnss_<distinctive>.so.2 gets
    # dlopen()'d by every name-resolution call), the rogue
    # module name MUST surface in the JSON sample so operator
    # dashboard routes triage to the right module.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'passwd: files distinctive_attacker_mod\ngroup: files\nshadow: files\nhosts: files dns\n' > "${CONF}"
    run_wd
    cap | grep -q 'distinctive_attacker_mod'
}
