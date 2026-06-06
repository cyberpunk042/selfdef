#!/usr/bin/env bats
# L2 functional suite for usb-storage-mass-disable.
#
# usb-storage-mass-disable blocks USB mass storage at the kernel
# level. Profiles:
#   blocked → modprobe blacklist usb_storage + uas; also `rmmod`
#             them if currently loaded (immediate enforcement)
#   audited → modprobe install hook that logs every load attempt
#             but doesn't block (visibility-only, useful for
#             baselining what's currently expected)
#
# USB mass storage is a classic data-exfiltration + malware-
# introduction vector. On endpoints that don't legitimately use
# USB sticks, blocking the kernel modules closes the entire class.
#
# CRITICAL INVARIANTS:
#   - blocked profile triggers rmmod for currently-loaded modules
#     (immediate enforcement) — non-DRY only.
#   - audited profile does NOT trigger rmmod (visibility-only).
#   - Idempotent: byte-identical re-install doesn't fire rmmod.
#   - DRY_RUN protects modprobe.d + rmmod.
#
# Uses SELFDEF_MODPROBE_D env-var (already present).
#
# Run with: bats packaging/test/L2-usb-storage-mass-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/usb-storage-mass-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/lsmod" <<'LSEOF'
#!/usr/bin/env bash
# Emit configured loaded module set.
printf '%s\n' "${LSMOD_OUTPUT:-Module                  Size  Used by}"
exit 0
LSEOF
    chmod +x "${BIN}/lsmod"
    cat > "${BIN}/rmmod" <<'RMEOF'
#!/usr/bin/env bash
printf 'rmmod %s\n' "$*" >> "${RMMOD_LOG}"
exit 0
RMEOF
    chmod +x "${BIN}/rmmod"
    export RMMOD_LOG="${TMP}/rmmod.log"
    : > "${RMMOD_LOG}"
    CONF="${TMP}/usb-storage-mass-disable.toml"
    MODPROBE_D="${TMP}/modprobe.d"
    mkdir -p "${MODPROBE_D}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    RMMOD_LOG="${RMMOD_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_USB_DISABLE_CONFIG="${CONF}" \
    SELFDEF_MODPROBE_D="${MODPROBE_D}" \
    LSMOD_OUTPUT="${LSMOD_OUTPUT:-Module                  Size  Used by}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_USB_DISABLE_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_USB_DISABLE_CONFIG="${SELFDEF_USB_DISABLE_CONFIG}" \
        SELFDEF_MODPROBE_D="${MODPROBE_D}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_USB_DISABLE_CONFIG="${CONF}" \
        SELFDEF_MODPROBE_D="${MODPROBE_D}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be blocked|audited"* ]]
}

@test "blocked profile installs the blocked modprobe drop-in" {
    write_config "blocked"
    run_wd
    [ -f "${MODPROBE_D}/50-selfdef-usb-storage.conf" ]
    [ "$(stat -c '%a' "${MODPROBE_D}/50-selfdef-usb-storage.conf")" = "644" ]
}

@test "audited profile installs the audited modprobe drop-in" {
    write_config "audited"
    run_wd
    [ -f "${MODPROBE_D}/50-selfdef-usb-storage.conf" ]
}

@test "INVARIANT: blocked profile + module currently loaded → rmmod fires (immediate enforcement)" {
    write_config "blocked"
    # lsmod emits usb_storage as currently loaded.
    LSMOD_OUTPUT='Module                  Size  Used by
usb_storage            73728  0
uas                    24576  0' run_wd
    grep -q 'rmmod usb_storage' "${RMMOD_LOG}"
    grep -q 'rmmod uas' "${RMMOD_LOG}"
}

@test "INVARIANT: blocked profile + module NOT loaded → NO rmmod fired" {
    write_config "blocked"
    LSMOD_OUTPUT='Module                  Size  Used by' run_wd
    ! grep -q 'rmmod' "${RMMOD_LOG}"
}

@test "INVARIANT: audited profile does NOT trigger rmmod even if loaded (visibility-only)" {
    write_config "audited"
    LSMOD_OUTPUT='Module                  Size  Used by
usb_storage            73728  0' run_wd
    # audited is visibility-only — no rmmod even with module loaded.
    ! grep -q 'rmmod' "${RMMOD_LOG}"
}

@test "INVARIANT: DRY_RUN does not install drop-in or fire rmmod" {
    write_config "blocked"
    LSMOD_OUTPUT='Module                  Size  Used by
usb_storage            73728  0' DRY_RUN=1 run_wd
    ! [ -f "${MODPROBE_D}/50-selfdef-usb-storage.conf" ]
    ! grep -q 'rmmod' "${RMMOD_LOG}"
}

@test "default profile is blocked (no profile key — the secure default)" {
    : > "${CONF}"
    run_wd
    [ -f "${MODPROBE_D}/50-selfdef-usb-storage.conf" ]
    cmp -s modules/usb-storage-mass-disable/configs/blocked.conf "${MODPROBE_D}/50-selfdef-usb-storage.conf"
}

@test "INVARIANT (blocked drop-in covers BOTH usb_storage + uas modules)" {
    write_config "blocked"
    run_wd
    grep -qE '(blacklist|install) usb_storage' "${MODPROBE_D}/50-selfdef-usb-storage.conf"
    grep -qE '(blacklist|install) uas' "${MODPROBE_D}/50-selfdef-usb-storage.conf"
}

@test "INVARIANT (audited drop-in content differs from blocked — audited logs, blocked denies)" {
    write_config "audited"
    run_wd
    sha_a="$(sha256sum "${MODPROBE_D}/50-selfdef-usb-storage.conf" | awk '{print $1}')"
    write_config "blocked"
    run_wd
    sha_b="$(sha256sum "${MODPROBE_D}/50-selfdef-usb-storage.conf" | awk '{print $1}')"
    [ "${sha_a}" != "${sha_b}" ]
}

@test "INVARIANT (profile transition audited → blocked): rewrites drop-in + fires rmmod on loaded modules" {
    write_config "audited"
    LSMOD_OUTPUT='Module                  Size  Used by
usb_storage            73728  0' run_wd
    : > "${RMMOD_LOG}"
    write_config "blocked"
    LSMOD_OUTPUT='Module                  Size  Used by
usb_storage            73728  0' run_wd
    grep -q 'rmmod usb_storage' "${RMMOD_LOG}"
}

@test "INVARIANT (idempotent mtime): byte-identical re-install preserves drop-in mtime" {
    write_config "blocked"
    run_wd
    mtime_before="$(stat -c '%Y' "${MODPROBE_D}/50-selfdef-usb-storage.conf")"
    sleep 1
    LSMOD_OUTPUT='Module                  Size  Used by' run_wd
    mtime_after="$(stat -c '%Y' "${MODPROBE_D}/50-selfdef-usb-storage.conf")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT (no render-timestamp in drop-in): defeats cmp -s idempotency guard" {
    write_config "blocked"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${MODPROBE_D}/50-selfdef-usb-storage.conf"
}
