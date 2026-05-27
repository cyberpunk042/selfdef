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
