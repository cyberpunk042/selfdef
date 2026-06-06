#!/usr/bin/env bats
# L2 functional suite for kdump-disable.
#
# kdump-disable stops + disables the kernel-crash-dump service
# family. kdump writes a snapshot of kernel memory (which contains
# encryption keys, passwords, in-flight secrets) to disk on crash
# — a treasure trove for forensic / exfil if the disk is later
# accessed. On a sovereign endpoint that doesn't run a kdump
# analysis workflow, the dump is pure data-exposure surface.
#
# Acts on 3 candidate units (kdump.service / kexec-tools.service
# / kdump-tools.service — Debian/Ubuntu/RHEL/SUSE variants).
# Profiles: stop | mask. DRY_RUN=1 → no system changes.
#
# Reuses the L2-at-disable.bats / L2-avahi-disable.bats installer
# test pattern.
#
# Run with: bats packaging/test/L2-kdump-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
case "$1" in
    list-unit-files)
        # Configurable per-unit presence via env var.
        case "$2" in
            kdump.service)        present="${KDUMP_PRESENT:-1}" ;;
            kexec-tools.service)  present="${KEXEC_PRESENT:-0}" ;;
            kdump-tools.service)  present="${KDUMPTOOLS_PRESENT:-0}" ;;
            *)                    present=0 ;;
        esac
        if [[ "${present}" == "1" ]]; then
            printf 'UNIT FILE     STATE\n%s   enabled\n' "$2"
            exit 0
        else
            exit 1
        fi ;;
esac
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/kdump-disable.toml"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_KDUMP_DISABLE_CONFIG="${CONF}" \
    KDUMP_PRESENT="${KDUMP_PRESENT:-1}" \
    KEXEC_PRESENT="${KEXEC_PRESENT:-0}" \
    KDUMPTOOLS_PRESENT="${KDUMPTOOLS_PRESENT:-0}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_KDUMP_DISABLE_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_KDUMP_DISABLE_CONFIG="${SELFDEF_KDUMP_DISABLE_CONFIG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile value → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_KDUMP_DISABLE_CONFIG="${CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be mask|stop"* ]]
}

@test "no kdump variants present → no mutation" {
    write_config "mask"
    KDUMP_PRESENT=0 KEXEC_PRESENT=0 KDUMPTOOLS_PRESENT=0 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "Debian variant (kdump-tools.service) present → acts on it only" {
    write_config "mask"
    KDUMP_PRESENT=0 KEXEC_PRESENT=0 KDUMPTOOLS_PRESENT=1 run_wd
    grep -q 'systemctl mask kdump-tools.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask kdump.service' "${SYSEOF_LOG}"
}

@test "RHEL variant (kdump.service) present → acts on it only" {
    write_config "mask"
    KDUMP_PRESENT=1 KEXEC_PRESENT=0 KDUMPTOOLS_PRESENT=0 run_wd
    grep -q 'systemctl mask kdump.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask kdump-tools.service' "${SYSEOF_LOG}"
}

@test "all 3 variants present → acts on all 3" {
    write_config "mask"
    KDUMP_PRESENT=1 KEXEC_PRESENT=1 KDUMPTOOLS_PRESENT=1 run_wd
    grep -q 'systemctl mask kdump.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask kexec-tools.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask kdump-tools.service' "${SYSEOF_LOG}"
}

@test "DRY_RUN=1 → no mutation" {
    write_config "mask"
    DRY_RUN=1 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "stop profile → stop + disable, NO mask" {
    write_config "stop"
    KDUMP_PRESENT=1 run_wd
    grep -q 'systemctl stop kdump.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable kdump.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask kdump.service' "${SYSEOF_LOG}"
}

@test "default profile is mask (no profile key in config)" {
    : > "${CONF}"
    run_wd
    grep -q 'systemctl mask kdump.service' "${SYSEOF_LOG}"
}
