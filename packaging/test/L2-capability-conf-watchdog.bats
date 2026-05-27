#!/usr/bin/env bats
# L2 bats functional tests for the capability-conf-watchdog scan script.
#
# /etc/security/capability.conf (pam_cap) grants Linux capabilities to users
# at login. A grant of a privilege-escalation-grade capability
# (cap_setuid/cap_sys_admin/cap_dac_override/…) to a user is a persistence /
# privesc signature (T1548). Severity:
#   ok    → no delta
#   warn  → any grant added/removed/changed
#   alert → a NEWLY-ADDED grant containing a dangerous capability
#
# Run with: bats packaging/test/L2-capability-conf-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd/capability-conf-watchdog.sh"

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
    CONF="${TMP}/capability.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_CAPCONF_PROFILE="${PROFILE:-report}" \
    SELFDEF_CAPCONF_BASELINE="${BASELINE}" \
    SELFDEF_CAPCONF_FILE="${CONF_V:-$CONF}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf 'cap_net_raw netuser\n' > "${CONF}"
}

@test "no capability.conf → ok / no_capability_conf" {
    CONF_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_capability_conf"'
    cap | grep -q '"severity":"ok"'
}

@test "benign capability.conf, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged capability.conf on second run → ok / capability_conf_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"capability_conf_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a newly-added dangerous capability grant → alert / capability_conf_dangerous_grant" {
    seed_benign
    run_wd
    printf 'cap_net_raw netuser\ncap_sys_admin eviluser\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"capability_conf_dangerous_grant"'
    cap | grep -q '"severity":"alert"'
}

@test "a benign non-dangerous grant change → warn / capability_conf_changed" {
    seed_benign
    run_wd
    printf 'cap_net_bind_service netuser\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"capability_conf_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign non-dangerous capability.conf is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "enforce profile exits non-zero on a dangerous grant" {
    seed_benign
    run_wd
    printf 'cap_net_raw netuser\ncap_setuid eviluser\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
