#!/usr/bin/env bats
# L2 bats functional tests for the crypttab-watchdog scan script.
#
# /etc/crypttab's `keyscript=` option runs a program AS ROOT at early boot
# to obtain the unlock key — a rogue keyscript is root-exec-at-boot
# persistence; a keyfile under a writable root is an unlock-key compromise.
# Entry format: `target source keyfile options`.
#
# Runs the actual scan script with `logger` shadowed on PATH and the
# crypttab in a tmp sandbox via SELFDEF_CRYPTTAB_FILE.
#
# Run with: bats packaging/test/L2-crypttab-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/crypttab-watchdog/systemd/crypttab-watchdog.sh"
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
    CRYPTTAB="${TMP}/crypttab"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_CRYPTTAB_PROFILE="${PROFILE:-report}" \
    SELFDEF_CRYPTTAB_BASELINE="${BASELINE}" \
    SELFDEF_CRYPTTAB_FILE="${CRYPTTAB_F:-$CRYPTTAB}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no crypttab → ok / no_crypttab" {
    CRYPTTAB_F="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_crypttab"'
    cap | grep -q '"severity":"ok"'
}

@test "benign crypttab, first run → ok / baseline_initial" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged crypttab on second run → ok / crypttab_intact" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"crypttab_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "keyscript under a writable root → alert / crypttab_suspicious" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd                                   # benign baseline
    printf 'data /dev/sda2 none luks,keyscript=/tmp/.getkey\n' > "${CRYPTTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"crypttab_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "keyfile under /dev/shm → alert" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    printf 'data /dev/sda2 /dev/shm/k luks\n' > "${CRYPTTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a bare/relative keyscript → alert" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    printf 'data /dev/sda2 none luks,keyscript=getkey\n' > "${CRYPTTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign options change → warn / crypttab_changed" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    printf 'data /dev/sda2 none luks,discard\n' > "${CRYPTTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"crypttab_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "keyfile=none + no keyscript is NOT flagged" {
    printf 'data /dev/sda2 none luks,discard\nroot UUID=abcd none luks\n' > "${CRYPTTAB}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a keyfile under /etc is NOT flagged" {
    printf 'data /dev/sda2 /etc/luks-keys/data.key luks\n' > "${CRYPTTAB}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious keyscript" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    printf 'data /dev/sda2 none luks,keyscript=/tmp/.getkey\n' > "${CRYPTTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — crypttab inventory enumerates LUKS-unlock root-exec surface)" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (keyscript under /var/tmp): writable-root expansion" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    printf 'data /dev/sda2 none luks,keyscript=/var/tmp/.getkey\n' > "${CRYPTTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (keyscript under /home): user-writable hijack coverage" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    printf 'data /dev/sda2 none luks,keyscript=/home/user/.getkey\n' > "${CRYPTTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (keyfile under /tmp → alert): keyfile vs keyscript axis-symmetric" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    printf 'data /dev/sda2 /tmp/key luks\n' > "${CRYPTTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (keyfile under /var/tmp → alert): writable-root expansion on keyfile axis" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    printf 'data /dev/sda2 /var/tmp/key luks\n' > "${CRYPTTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable crypttab file → alert)" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    chmod 0666 "${CRYPTTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-crypttab -- ')
    [ "${main_count}" = "1" ]
}
