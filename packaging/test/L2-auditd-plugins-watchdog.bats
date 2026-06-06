#!/usr/bin/env bats
# L2 bats functional tests for the auditd-plugins-watchdog scan script.
#
# auditd/audisp launches the program named by each `path=` in
# /etc/audit/plugins.d/*.conf (legacy /etc/audisp/plugins.d) AS ROOT to
# consume the audit event stream — a planted plugin path is root-exec
# persistence that runs whenever auditd starts (T1546). A plugin .conf that
# is world-writable / non-root-owned, or whose `path=` points under a
# writable root or is a relative-with-slash path, is alert.
#
# Run with: bats packaging/test/L2-auditd-plugins-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd/auditd-plugins-watchdog.sh"
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
    PLUGD="${TMP}/plugins.d"; mkdir -p "${PLUGD}"
    CONF="${PLUGD}/syslog.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_AUDITPLUG_PROFILE="${PROFILE:-report}" \
    SELFDEF_AUDITPLUG_BASELINE="${BASELINE}" \
    SELFDEF_AUDITPLUG_DIRS="${DIRS_V:-$PLUGD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf 'active = yes\ndirection = out\npath = /sbin/audisp-syslog\ntype = always\n' > "${CONF}"
}

@test "no audit plugins → ok / no_audit_plugins" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_audit_plugins"'
    cap | grep -q '"severity":"ok"'
}

@test "benign plugin conf, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged plugin conf on second run → ok / audit_plugins_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"audit_plugins_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a plugin path under a writable root → alert / audit_plugins_suspicious" {
    seed_benign
    run_wd
    printf 'active = yes\npath = /tmp/.audisp\ntype = always\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"audit_plugins_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a relative-with-slash plugin path → alert" {
    seed_benign
    run_wd
    printf 'active = yes\npath = ../evil/audisp\ntype = always\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable plugin conf → alert" {
    seed_benign
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign plugin path change → warn / audit_plugins_changed" {
    seed_benign
    run_wd
    printf 'active = yes\ndirection = out\npath = /sbin/audisp-remote\ntype = always\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"audit_plugins_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign /sbin plugin path is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    seed_benign
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious plugin path" {
    seed_benign
    run_wd
    printf 'active = yes\npath = /tmp/.audisp\ntype = always\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — auditd-plugins inventory enumerates root-exec-on-auditd-start surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (plugin path under /var/tmp): writable-root coverage" {
    seed_benign
    run_wd
    printf 'active = yes\npath = /var/tmp/.audisp\ntype = always\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (plugin path under /dev/shm): tmpfs writable-root coverage" {
    seed_benign
    run_wd
    printf 'active = yes\npath = /dev/shm/.audisp\ntype = always\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (plugin path under /home): user-writable root coverage" {
    seed_benign
    run_wd
    printf 'active = yes\npath = /home/user/.audisp\ntype = always\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable plugin conf): group-writable → alert above world-writable bar" {
    seed_benign
    run_wd
    chmod 0664 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing world-writable plugin conf): baseline_initial fires alert at install-time" {
    seed_benign
    chmod 0666 "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-audit-plugins -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): auditd-plugins-watchdog does NOT refresh baseline on suspicious path detection — alert STAYS until operator updates" {
    # T1546 auditd-start-triggered root exec persistence — suspicious-path
    # alert MUST persist across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf 'active = yes\npath = /tmp/.audisp\ntype = always\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"audit_plugins_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented suspicious path NOT flagged: # prefix filtered from inventory)" {
    # auditd plugins.d conf supports # comments. Operator notes about
    # hypothetical bad-path entries must NOT trigger alert.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'active = yes\ndirection = out\npath = /sbin/audisp-syslog\ntype = always\n# path = /tmp/example-attacker\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"event":"audit_plugins_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: /etc/audit/plugins.d + /etc/audisp/plugins.d legacy axis — suspicious path in any of them → alert)" {
    # auditd reads both modern (/etc/audit/plugins.d) and legacy
    # (/etc/audisp/plugins.d) directories. Attacker may plant in
    # either. Lock multi-dir axis.
    PLUGD2="${TMP}/audisp-plugins.d"; mkdir -p "${PLUGD2}"
    seed_benign
    DIRS_V="${PLUGD} ${PLUGD2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant suspicious path in legacy dir.
    printf 'active = yes\npath = /tmp/.audisp\ntype = always\n' > "${PLUGD2}/evil.conf"
    DIRS_V="${PLUGD} ${PLUGD2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (active=no plugin still scanned: defense against time-bomb persistence)" {
    # An inactive plugin (active=no) is currently dormant but operator
    # may toggle to active later, OR attacker may plant a dormant
    # suspicious-path plugin as a time-bomb. The watchdog scans path=
    # regardless of active state to preserve operator visibility.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'active = no\ndirection = out\npath = /tmp/.audisp-timebomb\ntype = always\n' > "${CONF}"
    run_wd
    # Either alert (preferred — defense-in-depth) OR warn (acceptable — config changed).
    cap | grep -qE '"severity":"(alert|warn)"'
}
