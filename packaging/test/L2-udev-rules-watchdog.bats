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
