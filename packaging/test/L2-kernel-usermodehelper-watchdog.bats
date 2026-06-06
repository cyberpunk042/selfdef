#!/usr/bin/env bats
# L2 bats functional tests for the kernel-usermodehelper-watchdog scan
# script.
#
# The kernel EXECUTES these paths AS ROOT (kernel context) on triggers an
# unprivileged user can often cause: kernel.modprobe (module autoload),
# kernel.hotplug (legacy; should be empty), kernel.poweroff_cmd. They are
# read live from /proc/sys/kernel and set persistently from sysctl.conf /
# sysctl.d/*.conf. `kernel.modprobe=/tmp/x` is a classic local privilege
# escalation (T1574 / T1548). A genuinely distinct mechanism: it reads a
# (here, faked) /proc tree AND scans sysctl files.
#
# Runs the actual scan script with `logger` shadowed on PATH, a faked
# PROC_DIR and sysctl sandbox via SELFDEF_KUMH_*; locks the
# `"severity":"alert"` token SDD-062 routes on + the D-6 fail-loud path.
#
# Run with: bats packaging/test/L2-kernel-usermodehelper-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd/kernel-usermodehelper-watchdog.sh"
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
    PROC="${TMP}/proc"; mkdir -p "${PROC}"
    SYSDIR="${TMP}/sysctl.d"; mkdir -p "${SYSDIR}"
    SYSCONF="${TMP}/sysctl.conf"
    NOSYS="${TMP}/nonexistent-sysctl.conf"
}

teardown() { rm -rf "${TMP}"; }

# helper <name> <value> — write a faked /proc/sys/kernel/<name>.
helper() { printf '%s' "$2" > "${PROC}/$1"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_KUMH_PROFILE="${PROFILE:-report}" \
    SELFDEF_KUMH_BASELINE="${BASELINE}" \
    SELFDEF_KUMH_PROC_DIR="${PROC_DIR:-$PROC}" \
    SELFDEF_KUMH_SYSCTL_DIRS="${SYSDIR}" \
    SELFDEF_KUMH_SYSCTL_FILES="${SYSCTL_FILES:-$NOSYS}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no helpers + no sysctl present → ok / no_usermodehelper" {
    PROC_DIR="${TMP}/noproc" run_wd
    cap | grep -q '"event":"no_usermodehelper"'
    cap | grep -q '"severity":"ok"'
}

@test "benign helper values, first run → ok / baseline_initial" {
    helper modprobe /sbin/modprobe
    helper hotplug ''
    helper poweroff_cmd /sbin/poweroff
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged helpers on second run → ok / usermodehelper_intact" {
    helper modprobe /sbin/modprobe
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"usermodehelper_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — the SDD-062 contract token
# ============================================================

@test "kernel.modprobe pointing under a writable root → alert" {
    helper modprobe /tmp/evil
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "relative (non-absolute) modprobe helper → alert" {
    helper modprobe relmodprobe
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "non-empty kernel.hotplug (deprecated) → alert" {
    helper hotplug /sbin/hotplug
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "sysctl.conf setting kernel.modprobe to a writable path → alert" {
    printf 'kernel.modprobe = /dev/shm/x\n' > "${SYSCONF}"
    SYSCTL_FILES="${SYSCONF}" run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "benign helper value changed after baseline → warn / usermodehelper_changed" {
    helper modprobe /sbin/modprobe
    run_wd
    helper modprobe /usr/sbin/modprobe
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"usermodehelper_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "standard /sbin helpers + empty hotplug are NOT flagged" {
    helper modprobe /sbin/modprobe
    helper hotplug ''
    helper poweroff_cmd /sbin/poweroff
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a commented-out sysctl modprobe line is NOT flagged" {
    helper modprobe /sbin/modprobe
    printf '# kernel.modprobe = /tmp/evil\n' > "${SYSCONF}"
    SYSCTL_FILES="${SYSCONF}" run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile + SDD-061 D-6 fail-loud
# ============================================================

@test "enforce profile exits non-zero on an alert" {
    helper modprobe /tmp/evil
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    helper modprobe /sbin/modprobe
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — kernel-usermodehelper inventory enumerates kernel-context root-exec triggers)" {
    helper modprobe /sbin/modprobe
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (kernel.modprobe under /var/tmp): writable-root expansion" {
    helper modprobe /var/tmp/evil
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (kernel.modprobe under /dev/shm): tmpfs writable-root coverage" {
    helper modprobe /dev/shm/evil
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (kernel.modprobe under /home): user-writable hijack coverage" {
    helper modprobe /home/user/evil
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (kernel.poweroff_cmd under /tmp): poweroff_cmd axis writable-root coverage" {
    # poweroff_cmd is triggered by halt/shutdown — a planted writable
    # path runs at shutdown time AS ROOT.
    helper poweroff_cmd /tmp/evil-shutdown
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (sysctl.d drop-in also scanned — not only main sysctl.conf)" {
    helper modprobe /sbin/modprobe
    printf 'kernel.modprobe = /tmp/dropin-evil\n' > "${SYSDIR}/99-evil.conf"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (sysctl line with whitespace tolerance — kernel.modprobe  =  /tmp/evil)" {
    helper modprobe /sbin/modprobe
    printf 'kernel.modprobe  =  /tmp/evil\n' > "${SYSCONF}"
    SYSCTL_FILES="${SYSCONF}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    helper modprobe /sbin/modprobe
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-kernel-usermodehelper -- ')
    [ "${main_count}" = "1" ]
}
