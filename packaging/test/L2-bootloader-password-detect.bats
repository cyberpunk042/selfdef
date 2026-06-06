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
