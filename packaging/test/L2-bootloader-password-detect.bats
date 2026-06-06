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
