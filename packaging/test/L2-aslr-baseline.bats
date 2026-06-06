#!/usr/bin/env bats
# L2 functional suite for aslr-baseline.
#
# aslr-baseline writes /etc/sysctl.d/50-selfdef-aslr.conf with
# kernel.randomize_va_space=2 (full ASLR — stack, mmap, brk, vdso
# all randomized) AND applies it live via `sysctl -w`. Full ASLR
# is foundational defense against memory-corruption exploits that
# rely on predictable addresses (ROP gadgets, libc base, heap
# layouts).
#
# Default Linux kernels usually ship with randomize_va_space=2
# already (the secure default), but operators / distros can flip
# it via boot args, init scripts, or kdump-induced kernel
# regressions. This baseline pins it.
#
# Only one profile: full. Refuses to apply with any other value
# (defensive — don't let a typo silently downgrade ASLR).
#
# Uses SELFDEF_ASLR_DROPIN env-var (added 2026-06-06) to point at
# a fixture path instead of the live /etc/sysctl.d.
#
# Run with: bats packaging/test/L2-aslr-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/sysctl" <<'SCEOF'
#!/usr/bin/env bash
printf 'sysctl %s\n' "$*" >> "${SCTL_LOG}"
case "$1" in
    -n) printf '2\n' ;;             # report current value
esac
exit 0
SCEOF
    chmod +x "${BIN}/sysctl"
    export SCTL_LOG="${TMP}/sysctl.log"
    : > "${SCTL_LOG}"
    CONF="${TMP}/aslr-baseline.toml"
    DROPIN="${TMP}/50-selfdef-aslr.conf"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SCTL_LOG="${SCTL_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_ASLR_CONFIG="${CONF}" \
    SELFDEF_ASLR_DROPIN="${DROPIN}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_ASLR_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_ASLR_CONFIG="${SELFDEF_ASLR_CONFIG}" \
        SELFDEF_ASLR_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "INVARIANT: any non-full profile → die (refuse to silently downgrade ASLR)" {
    write_config "partial"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_ASLR_CONFIG="${CONF}" \
        SELFDEF_ASLR_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be full"* ]]
    # No drop-in written, no sysctl fired.
    ! [ -f "${DROPIN}" ]
    ! grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "full profile writes drop-in + applies live via sysctl -w" {
    write_config "full"
    run_wd
    [ -f "${DROPIN}" ]
    # Drop-in carries the header marker + the randomize_va_space line.
    grep -q 'managed-by: selfdef aslr-baseline' "${DROPIN}"
    grep -q 'kernel.randomize_va_space' "${DROPIN}"
    # sysctl -w fired live.
    grep -q 'sysctl -w kernel.randomize_va_space=2' "${SCTL_LOG}"
}

@test "drop-in content includes the timestamped header comment" {
    write_config "full"
    run_wd
    grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z' "${DROPIN}"
    grep -q 'profile=full' "${DROPIN}"
}

@test "INVARIANT: DRY_RUN does not write drop-in or fire sysctl" {
    write_config "full"
    DRY_RUN=1 run_wd
    ! [ -f "${DROPIN}" ]
    ! grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "drop-in is chmod 0644 (world-readable system-config convention for /etc/sysctl.d)" {
    write_config "full"
    run_wd
    perms="$(stat -c '%a' "${DROPIN}")"
    [ "${perms}" = "644" ]
}

@test "default profile is full (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'kernel.randomize_va_space' "${DROPIN}"
}

@test "second run is idempotent — drop-in still present, sysctl -w fires again (sysctl is itself idempotent)" {
    write_config "full"
    run_wd
    : > "${SCTL_LOG}"
    run_wd
    [ -f "${DROPIN}" ]
    # sysctl -w fires every run — that's by design (the wrapper applies
    # the value live regardless of file change). The drop-in is what
    # carries persistence across reboot.
    grep -q 'sysctl -w kernel.randomize_va_space=2' "${SCTL_LOG}"
}
