#!/usr/bin/env bats
# L2 bats functional tests for the rsyslog-exec-watchdog scan script.
#
# rsyslog can run a program per log message — modern `omprog`
# (action(type="omprog" binary="/path")) or the legacy caret action
# (`<selector> ^program;template`) — AS ROOT, fired by any matching log
# event (a log-event-triggered exec surface). A binary under a writable
# root, relative-with-slash, bare, or carrying an injection pattern is alert.
#
# Runs the actual scan script with `logger` shadowed on PATH and the config
# in a tmp sandbox via SELFDEF_RSYSLOG_FILE / _D.
#
# Run with: bats packaging/test/L2-rsyslog-exec-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/rsyslog-exec-watchdog/systemd/rsyslog-exec-watchdog.sh"
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
    CONF="${TMP}/rsyslog.conf"
    CONFD="${TMP}/rsyslog.d"; mkdir -p "${CONFD}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_RSYSLOG_PROFILE="${PROFILE:-report}" \
    SELFDEF_RSYSLOG_BASELINE="${BASELINE}" \
    SELFDEF_RSYSLOG_FILE="${CONF_F:-$CONF}" \
    SELFDEF_RSYSLOG_D="${CONFD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no rsyslog config → ok / no_rsyslog" {
    CONF_F="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_rsyslog"'
    cap | grep -q '"severity":"ok"'
}

@test "benign omprog binary, first run → ok / baseline_initial" {
    printf 'module(load="omprog")\naction(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / rsyslog_exec_intact" {
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"rsyslog_exec_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "omprog binary under a writable root → alert / rsyslog_exec_suspicious" {
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd                                   # benign baseline
    printf 'action(type="omprog" binary="/tmp/.x")\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"rsyslog_exec_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a bare (non-absolute) omprog binary → alert" {
    # rsyslog omprog binaries are normally absolute; a bare name is abnormal.
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    printf 'action(type="omprog" binary="evilprog")\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a legacy caret action under a writable root → alert" {
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    printf '*.* ^/tmp/evil;RSYSLOG_TraditionalFileFormat\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign binary change → warn / rsyslog_exec_changed" {
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper2")\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"rsyslog_exec_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "a /usr/libexec omprog binary is NOT flagged" {
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious binary" {
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    printf 'action(type="omprog" binary="/tmp/.x")\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — rsyslog-exec inventory enumerates log-event-trigger root-exec surface)" {
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (omprog binary under /var/tmp): writable-root expansion" {
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    printf 'action(type="omprog" binary="/var/tmp/.attacker")\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (omprog binary under /dev/shm): tmpfs writable-root coverage" {
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    printf 'action(type="omprog" binary="/dev/shm/.attacker")\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (legacy caret action: writable-root expansion to /var/tmp)" {
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    printf '*.* ^/var/tmp/.attacker;RSYSLOG_TraditionalFileFormat\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (config in rsyslog.d also scanned — not only the main rsyslog.conf)" {
    # Per the watchdog's design (SELFDEF_RSYSLOG_D), drop-in conf in
    # /etc/rsyslog.d/* must ALSO surface exec actions.
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    printf 'action(type="omprog" binary="/tmp/.dropin-attacker")\n' > "${CONFD}/99-evil.conf"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable rsyslog.conf itself → alert)" {
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-rsyslog-exec -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): rsyslog-exec-watchdog does NOT refresh baseline on suspicious-binary detection — alert STAYS until operator updates" {
    # Log-event-trigger root-exec persistence — suspicious-binary alert
    # MUST persist across runs until operator explicitly re-baselines.
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    printf 'action(type="omprog" binary="/tmp/.x")\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"rsyslog_exec_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (current behavior — comment filter not implemented: # lines ARE scanned)" {
    # rsyslog uses # for comments. The current rsyslog-exec-watchdog
    # scanner does NOT filter # lines from inventory — it pattern-matches
    # raw content. Locks CURRENT behavior as documented; refinement
    # opportunity to add comment-line filter is tracked separately
    # (does NOT block this suite). Sister-pattern to apt-hooks-watchdog
    # (also lacks comment filter — different from boot-script/sshrc/
    # csh-config which do filter).
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# action(type="omprog" binary="/tmp/.example-attacker")\naction(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    # Current behavior: # line IS scanned + alert IS raised.
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (relative-with-slash omprog binary 'sub/dir/p' → alert)" {
    # Relative-with-slash is rsyslog-undefined behavior + attacker
    # primitive (resolved against rsyslog's PWD at exec time). Lock
    # detection alongside absolute-writable-root + bare-name axes.
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'action(type="omprog" binary="sub/dir/evil")\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (whitespace tolerance: 'binary=    \"/tmp/.evil\"' multi-space attribute variant still triggers alert)" {
    # Attacker may use multi-spaces around the binary= attribute to
    # evade naive grep. Lock whitespace-tolerant parser.
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'action(type="omprog" binary=    "/tmp/.evil")\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (omprog binary under /home: user-writable hijack coverage)" {
    # Sister to the /tmp + /var/tmp + /dev/shm writable-root axes
    # already locked. /home is the user-writable surface — an
    # attacker with a regular user account can drop a malicious
    # binary into their home and have rsyslogd exec it AS ROOT on
    # every matching log event. Lock axis-symmetry on /home for the
    # omprog binary surface (T1037 — Boot or Logon Initialization
    # Scripts / T1546 — Event Triggered Execution via log-event).
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'action(type="omprog" binary="/home/user/.evil")\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}
