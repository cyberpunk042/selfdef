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
