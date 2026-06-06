#!/usr/bin/env bats
# L2 functional suite for kernel-lockdown.
#
# kernel-lockdown installs sysctl drop-ins under /etc/sysctl.d that
# tighten kernel behavior. Two profiles:
#   balanced → kptr_restrict, dmesg_restrict, ptrace_scope=2,
#              unprivileged_bpf_disabled, etc. (the always-safe
#              baseline)
#   strict   → adds kernel.modules_disabled=1 — IRREVERSIBLE until
#              REBOOT. The script REQUIRES an explicit operator
#              acknowledgment (acknowledge_modules_disabled = true)
#              before applying strict — refuse-to-brick guard.
#
# CRITICAL INVARIANTS this suite locks:
#   1. strict without acknowledgment → die (refuse-to-brick).
#   2. Profile downgrade (strict→balanced) removes the strict drop-in.
#   3. Idempotent: byte-identical re-install is a no-op.
#   4. DRY_RUN protects /etc/sysctl.d + sysctl --system invocation.
#
# Uses SELFDEF_SYSCTL_DIR + SELFDEF_KERNEL_LOCKDOWN_SYSCTL env-vars
# (already present in the script) for L2 testability. Live default
# behavior unchanged.
#
# Run with: bats packaging/test/L2-kernel-lockdown.bats

WD="${BATS_TEST_DIRNAME}/../../modules/kernel-lockdown/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/sysctl" <<'SCEOF'
#!/usr/bin/env bash
printf 'sysctl %s\n' "$*" >> "${SCTL_LOG}"
exit 0
SCEOF
    chmod +x "${BIN}/sysctl"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    export SCTL_LOG="${TMP}/sysctl.log"
    : > "${SCTL_LOG}"
    CONF="${TMP}/kernel-lockdown.toml"
    SYSCTL_DIR="${TMP}/sysctl.d"
    SYSCTL_SRC="${TMP}/sysctl-src"
    mkdir -p "${SYSCTL_DIR}" "${SYSCTL_SRC}"
    # Drop fixture sysctl source files (mirroring modules/kernel-lockdown/sysctl/).
    printf 'kernel.kptr_restrict = 2\n' > "${SYSCTL_SRC}/balanced.conf"
    printf 'kernel.modules_disabled = 1\n' > "${SYSCTL_SRC}/strict.conf"
}

teardown() { rm -rf "${TMP}"; }

# write_config <profile> [ack]
write_config() {
    local profile="$1" ack="${2:-false}"
    printf 'profile = "%s"\n' "${profile}" > "${CONF}"
    printf 'acknowledge_modules_disabled = %s\n' "${ack}" >> "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SCTL_LOG="${SCTL_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_KERNEL_LOCKDOWN_CONFIG="${CONF}" \
    SELFDEF_KERNEL_LOCKDOWN_SYSCTL="${SYSCTL_SRC}" \
    SELFDEF_SYSCTL_DIR="${SYSCTL_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_KERNEL_LOCKDOWN_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_KERNEL_LOCKDOWN_CONFIG="${SELFDEF_KERNEL_LOCKDOWN_CONFIG}" \
        SELFDEF_KERNEL_LOCKDOWN_SYSCTL="${SYSCTL_SRC}" \
        SELFDEF_SYSCTL_DIR="${SYSCTL_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "missing sysctl source dir → die" {
    write_config "balanced"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_KERNEL_LOCKDOWN_CONFIG="${CONF}" \
        SELFDEF_KERNEL_LOCKDOWN_SYSCTL="${TMP}/missing-src" \
        SELFDEF_SYSCTL_DIR="${SYSCTL_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"sysctl source dir missing"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_KERNEL_LOCKDOWN_CONFIG="${CONF}" \
        SELFDEF_KERNEL_LOCKDOWN_SYSCTL="${SYSCTL_SRC}" \
        SELFDEF_SYSCTL_DIR="${SYSCTL_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be balanced|strict"* ]]
}

@test "INVARIANT: strict profile without acknowledgment → die (refuse-to-brick guard)" {
    write_config "strict" "false"      # NO acknowledgment
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_KERNEL_LOCKDOWN_CONFIG="${CONF}" \
        SELFDEF_KERNEL_LOCKDOWN_SYSCTL="${SYSCTL_SRC}" \
        SELFDEF_SYSCTL_DIR="${SYSCTL_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"IRREVERSIBLE until reboot"* ]]
    # No drop-ins should be installed despite the failure.
    ! [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
}

@test "balanced profile installs the balanced drop-in only" {
    write_config "balanced"
    run_wd
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf" ]
    ! [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
}

@test "strict profile WITH acknowledgment installs BOTH drop-ins" {
    write_config "strict" "true"
    run_wd
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf" ]
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
}

@test "INVARIANT: profile downgrade strict→balanced removes the strict drop-in" {
    # First install strict.
    write_config "strict" "true"
    run_wd
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
    # Switch to balanced.
    write_config "balanced"
    run_wd
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf" ]
    ! [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
}

@test "INVARIANT: idempotent — re-install with identical content is a no-op (no sysctl --system fired)" {
    write_config "balanced"
    run_wd                              # initial install
    : > "${SCTL_LOG}"                   # clear log
    run_wd                              # re-install — identical content
    # sysctl --system fires only when changes > 0; identical re-install → 0 changes.
    ! grep -q 'sysctl --system' "${SCTL_LOG}"
}

@test "INVARIANT: DRY_RUN does not install drop-ins or fire sysctl" {
    write_config "balanced"
    DRY_RUN=1 run_wd
    ! [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf" ]
    ! grep -q 'sysctl --system' "${SCTL_LOG}"
}

@test "balanced drop-in content matches the source exactly" {
    write_config "balanced"
    run_wd
    cmp -s "${SYSCTL_SRC}/balanced.conf" "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf"
}

@test "default profile is balanced (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf" ]
    ! [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
}
