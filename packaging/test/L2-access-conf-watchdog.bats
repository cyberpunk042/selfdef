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
