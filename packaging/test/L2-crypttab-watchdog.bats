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

@test "enforce profile exits non-zero on a suspicious keyscript" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    printf 'data /dev/sda2 none luks,keyscript=/tmp/.getkey\n' > "${CRYPTTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
