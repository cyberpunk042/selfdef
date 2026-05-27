#!/usr/bin/env bats
# L2 bats functional tests for the fstab-watchdog scan script.
#
# /etc/fstab entries are mounted AS ROOT at boot. Three high-signal classes:
#   - a loop/file-backed device under a writable root (/tmp/disk.img …) —
#     attacker-controlled filesystem image mounted at boot;
#   - a bind-mount that SHADOWS a sensitive path (/etc, /bin, /root/.ssh …);
#   - an explicit `suid` option re-enabling setuid where it was dropped.
# Entry format: `dev mountpoint fstype options …`.
#
# Runs the actual scan script with `logger` shadowed on PATH and the fstab
# in a tmp sandbox via SELFDEF_FSTAB_FILE / _D.
#
# Run with: bats packaging/test/L2-fstab-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/fstab-watchdog/systemd/fstab-watchdog.sh"

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
    FSTAB="${TMP}/fstab"
    FSTABD="${TMP}/fstab.d"; mkdir -p "${FSTABD}"
    BENIGN='UUID=11112222 / ext4 defaults 0 1
UUID=33334444 /home ext4 defaults,nosuid,nodev 0 2
tmpfs /tmp tmpfs defaults,nosuid,nodev,noexec 0 0
'
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_FSTAB_PROFILE="${PROFILE:-report}" \
    SELFDEF_FSTAB_BASELINE="${BASELINE}" \
    SELFDEF_FSTAB_FILE="${FSTAB_F:-$FSTAB}" \
    SELFDEF_FSTAB_D="${FSTABD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no fstab → ok / no_fstab" {
    FSTAB_F="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_fstab"'
    cap | grep -q '"severity":"ok"'
}

@test "benign fstab, first run → ok / baseline_initial" {
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged fstab on second run → ok / fstab_intact" {
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"fstab_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "a loop image under a writable root → alert / fstab_suspicious_mount" {
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd                                   # benign baseline
    printf '%s/tmp/disk.img /mnt ext4 loop 0 0\n' "${BENIGN}" > "${FSTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"fstab_suspicious_mount"'
    cap | grep -q '"severity":"alert"'
}

@test "a bind-mount shadowing /etc → alert" {
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    printf '%s/data/fakeetc /etc none bind 0 0\n' "${BENIGN}" > "${FSTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "an explicit suid option → alert" {
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    printf '%s/dev/sdb1 /data ext4 defaults,suid 0 2\n' "${BENIGN}" > "${FSTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign mount added → warn / fstab_changed" {
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    printf '%s/dev/sdc1 /backup ext4 defaults,nosuid,nodev 0 2\n' "${BENIGN}" > "${FSTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"fstab_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "a standard fstab is NOT flagged" {
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "enforce profile exits non-zero on a suspicious mount" {
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    printf '%s/tmp/disk.img /mnt ext4 loop 0 0\n' "${BENIGN}" > "${FSTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
