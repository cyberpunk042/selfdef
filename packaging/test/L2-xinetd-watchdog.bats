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

@test "enforce profile exits non-zero on a suspicious server" {
    xsvc /usr/sbin/in.telnetd > "${SVC}"
    run_wd
    xsvc /tmp/backdoor > "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
