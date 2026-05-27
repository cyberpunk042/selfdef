#!/usr/bin/env bats
# L2 bats functional tests for the sudo-conf-watchdog scan script.
#
# Covers the setuid-root sudo plugin-load surface: /etc/sudo.conf names
# the policy / I/O-logging plugins (.so) that sudo (SETUID-ROOT) loads on
# EVERY invocation via `Plugin <symbol> <path>`, and `Path plugin_dir <dir>`
# sets where relative plugin names resolve. A Plugin .so under a writable
# root, a relative-with-slash plugin path, or a writable plugin_dir loads
# attacker code into setuid-root sudo (T1574 / privilege escalation).
#
# Distinct grammar from the other watchdogs (keyword-prefixed directives,
# case-insensitive Plugin/Path). Runs the actual scan script with `logger`
# shadowed on PATH and config/baseline in a tmp sandbox via SELFDEF_SUDOCONF_*;
# locks the `"severity":"alert"` token SDD-062 routes on, and the SDD-061
# D-6 module-lib fail-loud path.
#
# Run with: bats packaging/test/L2-sudo-conf-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/sudo-conf-watchdog/systemd/sudo-conf-watchdog.sh"
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
    CONF="${TMP}/sudo.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_SUDOCONF_PROFILE="${PROFILE:-report}" \
    SELFDEF_SUDOCONF_BASELINE="${BASELINE}" \
    SELFDEF_SUDOCONF_FILES="${CONF}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no sudo.conf present → ok / no_sudo_conf" {
    run_wd
    cap | grep -q '"event":"no_sudo_conf"'
    cap | grep -q '"severity":"ok"'
}

@test "benign Plugin + Path, first run → ok / baseline_initial" {
    printf 'Plugin sudoers_policy sudoers.so\nPath plugin_dir /usr/libexec/sudo\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / sudo_conf_intact" {
    printf 'Plugin sudoers_policy sudoers.so\nPath plugin_dir /usr/libexec/sudo\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"sudo_conf_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — the SDD-062 contract token
# ============================================================

@test "Plugin .so under a writable root → alert" {
    printf 'Plugin policy /tmp/evil.so\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "relative-with-slash Plugin path → alert" {
    printf 'Plugin policy sub/dir/evil.so\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "Path plugin_dir pointing under a writable root → alert" {
    printf 'Path plugin_dir /dev/shm/sudo-plugins\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "bare writable root as plugin_dir → alert (SDD-063 gap closed)" {
    # plugin_dir = /tmp itself (no trailing component) makes relative plugin
    # names resolve from world-writable /tmp; previously missed by the file
    # helper, now caught by selfdef_is_writable_dir.
    printf 'Path plugin_dir /tmp\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "benign directive added after baseline → warn / sudo_conf_changed" {
    printf 'Plugin sudoers_policy sudoers.so\n' > "${CONF}"
    run_wd
    printf 'Plugin sudoers_policy sudoers.so\nPlugin sudoers_io sudoers.so\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"sudo_conf_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "relative plugin name without a slash is NOT flagged (resolves via plugin_dir)" {
    printf 'Plugin sudoers_policy sudoers.so\nPlugin sudoers_audit sudoers.so\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a commented-out writable Plugin line is NOT flagged" {
    printf '# Plugin policy /tmp/evil.so\nPlugin sudoers_policy sudoers.so\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile + SDD-061 D-6 fail-loud
# ============================================================

@test "enforce profile exits non-zero on an alert" {
    printf 'Plugin policy /tmp/evil.so\n' > "${CONF}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf 'Plugin sudoers_policy sudoers.so\n' > "${CONF}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}
