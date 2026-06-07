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

@test "INVARIANT (blocked drop-in carries selfdef-identifier header — operator audit trail + uninstall identification)" {
    # The drop-in carries '# selfdef usb-storage-mass-disable —
    # <profile>' as its first-line tracker (per configs/<profile>
    # .conf source). Locks the marker shape so uninstall +
    # tracking work.
    write_config "blocked"
    run_wd
    grep -qE '^# selfdef usb-storage-mass-disable' "${MODPROBE_D}/50-selfdef-usb-storage.conf"
}

@test "INVARIANT (audited drop-in carries selfdef-identifier header too — both profiles share ownership signal)" {
    write_config "audited"
    run_wd
    grep -qE '^# selfdef usb-storage-mass-disable' "${MODPROBE_D}/50-selfdef-usb-storage.conf"
}

@test "INVARIANT (drop-in re-arm after operator out-of-band deletion: re-creates drop-in)" {
    write_config "blocked"
    run_wd
    [ -f "${MODPROBE_D}/50-selfdef-usb-storage.conf" ]
    rm -f "${MODPROBE_D}/50-selfdef-usb-storage.conf"
    LSMOD_OUTPUT='Module                  Size  Used by' run_wd
    [ -f "${MODPROBE_D}/50-selfdef-usb-storage.conf" ]
    grep -qE '(blacklist|install) usb_storage' "${MODPROBE_D}/50-selfdef-usb-storage.conf"
}

@test "INVARIANT (no phantom rmmod: rmmod called ONLY for modules in lsmod, not blindly)" {
    # Lock that rmmod is gated on lsmod presence — calling rmmod
    # on absent modules would emit benign errors that pollute the
    # log and could mask real issues.
    write_config "blocked"
    LSMOD_OUTPUT='Module                  Size  Used by
usb_storage            73728  0' run_wd
    # usb_storage IS loaded → rmmod fired.
    grep -q 'rmmod usb_storage' "${RMMOD_LOG}"
    # uas NOT loaded → rmmod NOT fired for uas.
    ! grep -q 'rmmod uas' "${RMMOD_LOG}"
}

@test "INVARIANT (emit_status JSON: status=ok + profile + loaded-module-count surfaced for dashboard)" {
    write_config "blocked"
    output="$(LSMOD_OUTPUT='Module                  Size  Used by
usb_storage            73728  0
uas                    24576  0' run_wd 2>&1)"
    [[ "${output}" == *'"module":"usb-storage-mass-disable"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=blocked'* ]]
}

@test "INVARIANT (profile downgrade blocked → audited: rewrites drop-in + does NOT fire rmmod — bidirectional contract)" {
    # Sister to the audited → blocked transition test (which fires
    # rmmod). The reverse direction is operator-loosening; must
    # rewrite content but MUST NOT fire rmmod (audited is
    # visibility-only). Locks the bidirectional contract.
    write_config "blocked"
    LSMOD_OUTPUT='Module                  Size  Used by' run_wd
    : > "${RMMOD_LOG}"
    write_config "audited"
    LSMOD_OUTPUT='Module                  Size  Used by
usb_storage            73728  0' run_wd
    grep -qE '^# selfdef usb-storage-mass-disable' "${MODPROBE_D}/50-selfdef-usb-storage.conf"
    # audited NEVER fires rmmod regardless of transition direction.
    ! grep -q 'rmmod' "${RMMOD_LOG}"
}

@test "INVARIANT (audited drop-in mentions logging mechanism — install hook or audit token)" {
    # The audited drop-in's content must materially differ from
    # blocked — it must wire the modprobe install hook so kernel
    # logs every load attempt. Lock that the audited content
    # contains a recognizable audit/log token, not just a blank
    # placeholder.
    write_config "audited"
    run_wd
    grep -qE 'install|logger|audit|log' "${MODPROBE_D}/50-selfdef-usb-storage.conf"
}

@test "INVARIANT (rmmod failures non-fatal: blocked profile completes apply even if rmmod returns error)" {
    # On real hosts, a loaded module may have in-use references
    # (rmmod -f required). Failure of rmmod MUST NOT bubble up as
    # apply failure — the modprobe.d blacklist is the load-bearing
    # next-boot enforcement; rmmod is best-effort immediate.
    cat > "${BIN}/rmmod" <<'RMEOF'
#!/usr/bin/env bash
printf 'rmmod %s\n' "$*" >> "${RMMOD_LOG}"
exit 1
RMEOF
    chmod +x "${BIN}/rmmod"
    write_config "blocked"
    LSMOD_OUTPUT='Module                  Size  Used by
usb_storage            73728  0' run_wd
    # Drop-in still landed even though rmmod failed.
    [ -f "${MODPROBE_D}/50-selfdef-usb-storage.conf" ]
    grep -qE '(blacklist|install) usb_storage' "${MODPROBE_D}/50-selfdef-usb-storage.conf"
}

@test "INVARIANT (blocked profile covers BOTH usb_storage AND uas — full mass-storage class coverage)" {
    # Sister to many other watchdog/installer's multi-axis coverage
    # INVARIANT across the brain. USB Attached SCSI (uas) is the
    # newer-generation mass-storage transport, used by USB 3.0+
    # thumb drives that negotiate UAS instead of legacy BOT. An
    # attacker plugging in a UAS-only thumb drive would bypass a
    # usb_storage-only blacklist. Lock the complete class coverage:
    # blocked profile MUST blacklist BOTH usb_storage AND uas.
    # T1052 (Hardware Additions) data-exfil + T1091 (Replication
    # Through Removable Media) malware-introduction primitives both
    # close.
    write_config "blocked"
    run_wd
    grep -qE '(blacklist|install) usb_storage' "${MODPROBE_D}/50-selfdef-usb-storage.conf"
    grep -qE '(blacklist|install) uas' "${MODPROBE_D}/50-selfdef-usb-storage.conf"
}
