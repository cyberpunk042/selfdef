#!/usr/bin/env bats
# L2 bats functional tests for the sysusers-watchdog scan script.
#
# systemd-sysusers materializes the declarative users in sysusers.d/*.conf
# into /etc/passwd + /etc/group at boot. A `u` entry with uid 0 is a
# root-equivalent backdoor account; an `m` membership into a privileged group
# is privilege escalation (T1136 / T1098). Severity:
#   ok    → no delta
#   warn  → an entry added/changed/removed
#   alert → a .conf world-writable/non-root, a uid-0 `u` entry, or a
#           membership into a privileged group
#
# Run with: bats packaging/test/L2-sysusers-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/sysusers-watchdog/systemd/sysusers-watchdog.sh"

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
    CONFD="${TMP}/sysusers.d"; mkdir -p "${CONFD}"
    CONF="${CONFD}/myapp.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_SYSUSERS_PROFILE="${PROFILE:-report}" \
    SELFDEF_SYSUSERS_BASELINE="${BASELINE}" \
    SELFDEF_SYSUSERS_DIRS="${DIRS_V:-$CONFD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf 'u myapp 999 "My App Daemon"\ng myapp 999\n' > "${CONF}"
}

@test "no sysusers config → ok / no_sysusers" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_sysusers"'
    cap | grep -q '"severity":"ok"'
}

@test "benign sysusers conf, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged sysusers conf on second run → ok / sysusers_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"sysusers_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a uid-0 u entry → alert / sysusers_suspicious" {
    seed_benign
    run_wd
    printf 'u myapp 999 "My App Daemon"\ng myapp 999\nu backdoor 0 "root clone"\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"sysusers_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable sysusers conf → alert" {
    seed_benign
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign entry change → warn / sysusers_changed" {
    seed_benign
    run_wd
    printf 'u myapp 998 "My App Daemon"\ng myapp 998\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"sysusers_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign non-root sysusers conf is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "enforce profile exits non-zero on a uid-0 entry" {
    seed_benign
    run_wd
    printf 'u backdoor 0 "root clone"\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
