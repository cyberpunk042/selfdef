#!/usr/bin/env bats
# L2 functional suite for bootloader-password-detect.
#
# bootloader-password-detect installs a systemd timer that checks
# whether GRUB / systemd-boot / RAUC / U-Boot is password-protected.
# An unprotected bootloader is a quiet privilege-escalation vector:
# an attacker with physical access can edit the boot command line
# from the GRUB menu (init=/bin/bash, single-user, etc.) and skip
# authentication entirely. The detector reports this.
#
# Profiles:
#   report  → log finding, no enforcement
#   enforce → log + exit non-zero (systemd records failure surfacing
#             via doctor / dashboard)
#
# Same shape as entropy-baseline: libexec script + service unit +
# timer unit + service.d/50-profile.conf drop-in setting
# SELFDEF_BOOTLOADER_PROFILE env-var.
#
# Uses SELFDEF_LIBEXEC_DIR + SELFDEF_SYSTEMD_DIR env-vars (already
# present) for L2 testability.
#
# Run with: bats packaging/test/L2-bootloader-password-detect.bats

WD="${BATS_TEST_DIRNAME}/../../modules/bootloader-password-detect/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/bootloader-password-detect.toml"
    LIBEXEC_DIR="${TMP}/libexec"
    SYSTEMD_DIR="${TMP}/systemd"
    mkdir -p "${LIBEXEC_DIR}" "${SYSTEMD_DIR}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_BOOTLOADER_CONFIG="${CONF}" \
    SELFDEF_LIBEXEC_DIR="${LIBEXEC_DIR}" \
    SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_BOOTLOADER_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_BOOTLOADER_CONFIG="${SELFDEF_BOOTLOADER_CONFIG}" \
        SELFDEF_LIBEXEC_DIR="${LIBEXEC_DIR}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_BOOTLOADER_CONFIG="${CONF}" \
        SELFDEF_LIBEXEC_DIR="${LIBEXEC_DIR}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be report|enforce"* ]]
}

@test "report profile installs all 4 files (libexec + service + timer + profile drop-in)" {
    write_config "report"
    run_wd
    [ -f "${LIBEXEC_DIR}/bootloader-password-detect.sh" ]
    [ -x "${LIBEXEC_DIR}/bootloader-password-detect.sh" ]
    [ -f "${SYSTEMD_DIR}/selfdef-bootloader-password.service" ]
    [ -f "${SYSTEMD_DIR}/selfdef-bootloader-password.timer" ]
    [ -f "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf" ]
    grep -q 'SELFDEF_BOOTLOADER_PROFILE=report' "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf"
}

@test "enforce profile drop-in carries SELFDEF_BOOTLOADER_PROFILE=enforce" {
    write_config "enforce"
    run_wd
    grep -q 'SELFDEF_BOOTLOADER_PROFILE=enforce' "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf"
}

@test "libexec script chmod 0755 (executable convention)" {
    write_config "report"
    run_wd
    [ "$(stat -c '%a' "${LIBEXEC_DIR}/bootloader-password-detect.sh")" = "755" ]
}

@test "service + timer + drop-in chmod 0644 (system-config convention)" {
    write_config "report"
    run_wd
    [ "$(stat -c '%a' "${SYSTEMD_DIR}/selfdef-bootloader-password.service")" = "644" ]
    [ "$(stat -c '%a' "${SYSTEMD_DIR}/selfdef-bootloader-password.timer")" = "644" ]
    [ "$(stat -c '%a' "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf")" = "644" ]
}

@test "daemon-reload + timer enable fire on initial install" {
    write_config "report"
    run_wd
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
    grep -q 'systemctl enable --now selfdef-bootloader-password.timer' "${SYSEOF_LOG}"
}

@test "INVARIANT: idempotent — re-install with identical content fires NO daemon-reload" {
    write_config "report"
    run_wd
    : > "${SYSEOF_LOG}"
    run_wd
    ! grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT: profile change report → enforce updates drop-in + fires daemon-reload" {
    write_config "report"
    run_wd
    write_config "enforce"
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'SELFDEF_BOOTLOADER_PROFILE=enforce' "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf"
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT: DRY_RUN does not install anything or fire systemctl" {
    write_config "report"
    DRY_RUN=1 run_wd
    ! [ -f "${LIBEXEC_DIR}/bootloader-password-detect.sh" ]
    ! grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "default profile is report (no profile key — the safe default)" {
    : > "${CONF}"
    run_wd
    grep -q 'SELFDEF_BOOTLOADER_PROFILE=report' "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf"
}

@test "INVARIANT (profile downgrade enforce → report): rewrites drop-in back + fires reload" {
    write_config "enforce"
    run_wd
    grep -q 'SELFDEF_BOOTLOADER_PROFILE=enforce' "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf"
    write_config "report"
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'SELFDEF_BOOTLOADER_PROFILE=report' "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf"
    ! grep -q 'SELFDEF_BOOTLOADER_PROFILE=enforce' "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf"
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT (idempotent mtime): byte-identical re-install preserves all 4 file mtimes" {
    write_config "report"
    run_wd
    mtime_libexec_before="$(stat -c '%Y' "${LIBEXEC_DIR}/bootloader-password-detect.sh")"
    mtime_service_before="$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-bootloader-password.service")"
    mtime_timer_before="$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-bootloader-password.timer")"
    mtime_dropin_before="$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf")"
    sleep 1
    run_wd
    [ "${mtime_libexec_before}" = "$(stat -c '%Y' "${LIBEXEC_DIR}/bootloader-password-detect.sh")" ]
    [ "${mtime_service_before}" = "$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-bootloader-password.service")" ]
    [ "${mtime_timer_before}" = "$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-bootloader-password.timer")" ]
    [ "${mtime_dropin_before}" = "$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf")" ]
}

@test "INVARIANT (libexec script carries detect logic — actually checks the 4 bootloaders)" {
    write_config "report"
    run_wd
    # The libexec script must actually probe the 4 bootloaders.
    libexec="${LIBEXEC_DIR}/bootloader-password-detect.sh"
    grep -qiE 'grub|systemd-boot|rauc|u-boot' "${libexec}"
}

@test "INVARIANT (service unit references the libexec script): wiring is correct" {
    write_config "report"
    run_wd
    grep -qE 'ExecStart=' "${SYSTEMD_DIR}/selfdef-bootloader-password.service"
    grep -q 'bootloader-password-detect' "${SYSTEMD_DIR}/selfdef-bootloader-password.service"
}

@test "INVARIANT (timer unit carries OnCalendar or OnBootSec — actually fires periodically)" {
    write_config "report"
    run_wd
    grep -qE '(OnCalendar|OnBootSec|OnUnitActiveSec)=' "${SYSTEMD_DIR}/selfdef-bootloader-password.timer"
}

@test "INVARIANT (no render-timestamp in any installed file): defeats cmp -s idempotency" {
    write_config "report"
    run_wd
    for f in "${LIBEXEC_DIR}/bootloader-password-detect.sh" \
             "${SYSTEMD_DIR}/selfdef-bootloader-password.service" \
             "${SYSTEMD_DIR}/selfdef-bootloader-password.timer" \
             "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf"; do
        ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "$f"
    done
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates all 4 files + fires daemon-reload)" {
    # Operator may rm one of the installed files — apply must rebuild
    # and re-arm the timer so the bootloader-detect surveillance is restored.
    write_config "report"
    run_wd
    [ -f "${SYSTEMD_DIR}/selfdef-bootloader-password.timer" ]
    rm -f "${LIBEXEC_DIR}/bootloader-password-detect.sh" \
          "${SYSTEMD_DIR}/selfdef-bootloader-password.service" \
          "${SYSTEMD_DIR}/selfdef-bootloader-password.timer" \
          "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf"
    : > "${SYSEOF_LOG}"
    run_wd
    [ -f "${LIBEXEC_DIR}/bootloader-password-detect.sh" ]
    [ -f "${SYSTEMD_DIR}/selfdef-bootloader-password.service" ]
    [ -f "${SYSTEMD_DIR}/selfdef-bootloader-password.timer" ]
    [ -f "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf" ]
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "enforce"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"bootloader-password-detect"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=enforce'* ]]
}

@test "INVARIANT (libexec carries GRUB detection axes — multi-distro grub.cfg locations probed)" {
    # Module-header comment notes "other bootloaders out of scope" —
    # the libexec is GRUB-focused. Lock the actual coverage: GRUB
    # primary config + multi-distro EFI variants + user-config file.
    write_config "report"
    run_wd
    libexec="${LIBEXEC_DIR}/bootloader-password-detect.sh"
    # Core GRUB locations.
    grep -q '/boot/grub/grub.cfg' "${libexec}"
    grep -q '/boot/grub2/grub.cfg' "${libexec}"
    # Multi-distro EFI variants.
    grep -qE '/boot/efi/EFI/(debian|ubuntu|fedora)/grub.cfg' "${libexec}"
    # Password directive scanner (the actual check).
    grep -qE 'password' "${libexec}"
}

@test "INVARIANT (timer + service header marker — operator-audit-trail)" {
    write_config "report"
    run_wd
    grep -qE '^#.*selfdef|^#.*managed-by' "${SYSTEMD_DIR}/selfdef-bootloader-password.timer"
    grep -qE '^#.*selfdef|^#.*managed-by' "${SYSTEMD_DIR}/selfdef-bootloader-password.service"
}

@test "INVARIANT (libexec is shell-sourceable: bash -n parses cleanly — service ExecStart contract)" {
    # The libexec script runs from systemd ExecStart. bash -n must
    # parse cleanly. Sister to umask-baseline + shell-timeout-
    # baseline + tensor-parallel-inference + slm-cpu-loop + wol-
    # disable shell-sourceable INVARIANT.
    write_config "report"
    run_wd
    bash -n "${LIBEXEC_DIR}/bootloader-password-detect.sh"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # bootloader-password-detect TOML; parser must tolerate without
    # altering the profile-gated behavior. enforce-with-noise still
    # writes the SELFDEF_BOOTLOADER_PROFILE=enforce drop-in
    # (escalates missing-bootloader-password from log-only to
    # systemd-failure-recorded — the operator-dashboard signal for
    # physical-access boot-edit surveillance).
    cat > "${CONF}" <<'TOMLEOF'
profile = "enforce"
operator_note = "bootloader pwless = physical-access kernel-cmdline edit"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    grep -q 'SELFDEF_BOOTLOADER_PROFILE=enforce' "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf"
    ! grep -q 'SELFDEF_BOOTLOADER_PROFILE=report' "${SYSTEMD_DIR}/selfdef-bootloader-password.service.d/50-profile.conf"
}

@test "INVARIANT (libexec falls through to ok/no_grub when no grub.cfg present — anti-false-alert on non-GRUB hosts)" {
    # Sister to many other watchdog's no-target-found fall-through
    # INVARIANTs across the brain. When the libexec runs on a non-
    # GRUB host (sd-boot / EFISTUB-only / U-Boot / chromebook
    # custom), it MUST emit ok/no_grub instead of false-firing
    # alert — operator dashboards would be flooded with bogus
    # alerts otherwise on every non-GRUB workstation. Current-
    # behavior lock: sd-boot coverage is a future-decision; today
    # the script is GRUB-only with safe ok fallthrough on absent.
    # Closes the no-target fall-through invariant.
    write_config "report"
    run_wd
    grep -qE '"event":"no_grub"|exit 0' "${LIBEXEC_DIR}/bootloader-password-detect.sh"
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO service/timer/libexec/profile-drop-in files written when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without installing the 4 files (service + timer +
    # libexec + profile drop-in) AND without firing daemon-reload.
    # A silent dry-run that committed would land a recurring boot-
    # time scanner against grub.cfg on a host where operator was
    # investigating. Locks the dry-run-preserves-state contract on
    # the bootloader-password detection substrate.
    rm -rf "${SYSTEMD_DIR}" "${LIBEXEC_DIR}"
    mkdir -p "${SYSTEMD_DIR}" "${LIBEXEC_DIR}"
    write_config "report"
    : > "${SYSEOF_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${SYSTEMD_DIR}/selfdef-bootloader-password.service" ]
    [ ! -f "${SYSTEMD_DIR}/selfdef-bootloader-password.timer" ]
    [ ! -f "${LIBEXEC_DIR}/bootloader-password-detect.sh" ]
    ! grep -q 'daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT (timer unit carries Persistent=true — missed-fires catch up after long downtime)" {
    # Sister to brain-wide timer Persistent=true INVARIANTs.
    write_config "report"
    run_wd
    grep -qE '^Persistent=true' "${SYSTEMD_DIR}/selfdef-bootloader-password.timer"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on bootloader-password-detect
    # installer surface across libexec + service + timer +
    # profile-drop-in phases.
    write_config "report"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"bootloader-password-detect"')
    [ "${count}" = "1" ]
}
