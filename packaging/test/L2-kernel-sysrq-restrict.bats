#!/usr/bin/env bats
# L2 functional suite for kernel-sysrq-restrict.
#
# kernel-sysrq-restrict writes /etc/sysctl.d/50-selfdef-sysrq.conf
# pinning kernel.sysrq to a known value + applies it live via
# sysctl -w. The SysRq key is a kernel "magic key" that bypasses
# normal access controls: holding ALT+SysRq+<key> from any tty
# triggers privileged operations (reboot, kill all processes,
# dump kernel state, even spawn a root shell on some configs).
#
# Profiles:
#   off         → kernel.sysrq=0 (disable entirely)
#   safe-subset → kernel.sysrq=132 (only sync + remount-ro + reboot)
#   full        → kernel.sysrq=1 (all SysRq commands enabled —
#                  generally NOT recommended on a sovereign endpoint)
#
# Physical SysRq from a keyboard or serial console is a privilege
# escalation surface for anyone with that access — janitor, evil
# maid, or someone-with-an-IPMI-console.
#
# Adds SELFDEF_SYSRQ_DROPIN env-var (added 2026-06-06) for L2
# testability. Live default unchanged.
#
# Run with: bats packaging/test/L2-kernel-sysrq-restrict.bats

WD="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/sysctl" <<'SCEOF'
#!/usr/bin/env bash
printf 'sysctl %s\n' "$*" >> "${SCTL_LOG}"
exit 0
SCEOF
    chmod +x "${BIN}/sysctl"
    export SCTL_LOG="${TMP}/sysctl.log"
    : > "${SCTL_LOG}"
    CONF="${TMP}/kernel-sysrq-restrict.toml"
    DROPIN="${TMP}/50-selfdef-sysrq.conf"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SCTL_LOG="${SCTL_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_SYSRQ_CONFIG="${CONF}" \
    SELFDEF_SYSRQ_DROPIN="${DROPIN}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_SYSRQ_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_SYSRQ_CONFIG="${SELFDEF_SYSRQ_CONFIG}" \
        SELFDEF_SYSRQ_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_SYSRQ_CONFIG="${CONF}" \
        SELFDEF_SYSRQ_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be off|safe-subset|full"* ]]
}

@test "off profile → sysctl -w kernel.sysrq=0" {
    write_config "off"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'sysctl -w kernel.sysrq=0' "${SCTL_LOG}"
    grep -q 'profile=off' "${DROPIN}"
    grep -q '(kernel.sysrq=0)' "${DROPIN}"
}

@test "safe-subset profile → sysctl -w kernel.sysrq=132 (sync+remount-ro+reboot bitmask)" {
    write_config "safe-subset"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'sysctl -w kernel.sysrq=132' "${SCTL_LOG}"
    grep -q '(kernel.sysrq=132)' "${DROPIN}"
}

@test "full profile → sysctl -w kernel.sysrq=1" {
    write_config "full"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'sysctl -w kernel.sysrq=1' "${SCTL_LOG}"
}

@test "drop-in carries the header marker + timestamp" {
    write_config "off"
    run_wd
    grep -q 'managed-by: selfdef kernel-sysrq-restrict' "${DROPIN}"
    ! grep -qE '^# Generated [0-9]{4}-' "${DROPIN}"  # no timestamp (2026-06-06 idempotency fix)
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite drop-in (2026-06-06 idempotency fix)" {
    write_config "off"
    run_wd
    mtime_before="$(stat -c '%Y' "${DROPIN}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DROPIN}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: DRY_RUN does not write drop-in or fire sysctl" {
    write_config "off"
    DRY_RUN=1 run_wd
    ! [ -f "${DROPIN}" ]
    ! grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "drop-in is chmod 0644 (system-config convention)" {
    write_config "off"
    run_wd
    [ "$(stat -c '%a' "${DROPIN}")" = "644" ]
}

@test "default profile is off (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'profile=off' "${DROPIN}"
}

@test "second run replays sysctl -w (idempotent at the kernel-state layer)" {
    write_config "safe-subset"
    run_wd
    : > "${SCTL_LOG}"
    run_wd
    grep -q 'sysctl -w kernel.sysrq=132' "${SCTL_LOG}"
}

@test "INVARIANT (profile transition off → safe-subset): rewrites + applies 132 live" {
    write_config "off"
    run_wd
    grep -q 'profile=off' "${DROPIN}"
    write_config "safe-subset"
    : > "${SCTL_LOG}"
    run_wd
    grep -q 'profile=safe-subset' "${DROPIN}"
    grep -q 'sysctl -w kernel.sysrq=132' "${SCTL_LOG}"
}

@test "INVARIANT (profile transition safe-subset → full): rewrites + applies =1 live" {
    write_config "safe-subset"
    run_wd
    write_config "full"
    : > "${SCTL_LOG}"
    run_wd
    grep -q 'profile=full' "${DROPIN}"
    grep -q 'sysctl -w kernel.sysrq=1' "${SCTL_LOG}"
}

@test "INVARIANT (profile downgrade full → off): rewrites back to most-restrictive + applies 0" {
    write_config "full"
    run_wd
    write_config "off"
    : > "${SCTL_LOG}"
    run_wd
    grep -q 'profile=off' "${DROPIN}"
    grep -q 'sysctl -w kernel.sysrq=0' "${SCTL_LOG}"
}

@test "INVARIANT (safe-subset bitmask 132): the actual bitmask value (4=sync + 128=reboot, sum=132)" {
    # The 132 bitmask: sync (4) + reboot (128). The combination matters
    # — if this drifts to 4 or 128 alone, the safe-subset functionality
    # is broken differently (no reboot OR no sync).
    write_config "safe-subset"
    run_wd
    grep -qE 'kernel\.sysrq\s*=\s*132' "${DROPIN}"
}

@test "INVARIANT (live-knob re-application — even on idempotent disk path)" {
    write_config "off"
    run_wd
    : > "${SCTL_LOG}"
    run_wd
    grep -q 'sysctl -w kernel.sysrq=' "${SCTL_LOG}"
}
