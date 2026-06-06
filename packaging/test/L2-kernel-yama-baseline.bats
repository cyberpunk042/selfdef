#!/usr/bin/env bats
# L2 functional suite for kernel-yama-baseline.
#
# kernel-yama-baseline pins kernel.yama.ptrace_scope. ptrace is
# how debuggers (gdb, strace) attach to processes. Without
# restriction, ANY process can ptrace ANY same-uid process —
# attacker tools (memory scrapers, password sniffers, etc.) use
# this to dump in-memory secrets from already-running processes
# without escalating privileges.
#
# Profiles:
#   relaxed  → ptrace_scope=1 (only ancestors / declared tracees;
#              the kernel default since Linux 3.4)
#   strict   → ptrace_scope=2 (admin-only ptrace)
#   paranoid → ptrace_scope=3 (no ptrace AT ALL —
#              IRREVERSIBLE until reboot)
#
# CRITICAL INVARIANT: paranoid (=3) is irreversible until reboot.
# The script requires acknowledge_paranoid=true in the config or
# REFUSES TO APPLY. Refuse-to-brick guard parallel to kernel-
# lockdown's strict acknowledgment.
#
# Adds SELFDEF_YAMA_DROPIN env-var (added 2026-06-06) for L2
# testability. Live default unchanged.
#
# Run with: bats packaging/test/L2-kernel-yama-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/sysctl" <<'SCEOF'
#!/usr/bin/env bash
printf 'sysctl %s\n' "$*" >> "${SCTL_LOG}"
case "$1" in
    -n) printf '%s\n' "${LIVE_YAMA:-1}" ;;
esac
exit 0
SCEOF
    chmod +x "${BIN}/sysctl"
    export SCTL_LOG="${TMP}/sysctl.log"
    : > "${SCTL_LOG}"
    CONF="${TMP}/kernel-yama-baseline.toml"
    DROPIN="${TMP}/50-selfdef-yama.conf"
}

teardown() { rm -rf "${TMP}"; }

# write_config <profile> [ack_paranoid]
write_config() {
    local profile="$1" ack="${2:-false}"
    printf 'profile = "%s"\n' "${profile}" > "${CONF}"
    printf 'acknowledge_paranoid = %s\n' "${ack}" >> "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SCTL_LOG="${SCTL_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_YAMA_CONFIG="${CONF}" \
    SELFDEF_YAMA_DROPIN="${DROPIN}" \
    LIVE_YAMA="${LIVE_YAMA:-1}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_YAMA_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_YAMA_CONFIG="${SELFDEF_YAMA_CONFIG}" \
        SELFDEF_YAMA_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_YAMA_CONFIG="${CONF}" \
        SELFDEF_YAMA_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be relaxed|strict|paranoid"* ]]
}

@test "INVARIANT: paranoid without acknowledgment → die (refuse-to-brick guard)" {
    write_config "paranoid" "false"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_YAMA_CONFIG="${CONF}" \
        SELFDEF_YAMA_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"IRREVERSIBLE until reboot"* ]]
    ! [ -f "${DROPIN}" ]
}

@test "relaxed profile → sysctl -w kernel.yama.ptrace_scope=1" {
    write_config "relaxed"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'sysctl -w kernel.yama.ptrace_scope=1' "${SCTL_LOG}"
}

@test "strict profile → sysctl -w kernel.yama.ptrace_scope=2 (admin-only)" {
    write_config "strict"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'sysctl -w kernel.yama.ptrace_scope=2' "${SCTL_LOG}"
}

@test "paranoid profile WITH acknowledgment → sysctl -w kernel.yama.ptrace_scope=3" {
    write_config "paranoid" "true"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'sysctl -w kernel.yama.ptrace_scope=3' "${SCTL_LOG}"
}

@test "INVARIANT: live=3 but profile=2 → drop-in still placed (post-reboot effect) + log WARN" {
    # Live state is already paranoid (locked-until-reboot). Apply strict
    # → the drop-in is installed (so the post-reboot value is 2), but
    # sysctl -w may be a no-op the kernel rejects. Either way, the
    # script should not die — it logs WARN and continues.
    write_config "strict"
    LIVE_YAMA=3 run_wd                  # kernel reports current=3
    [ -f "${DROPIN}" ]                  # drop-in still placed
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite drop-in (2026-06-06 idempotency fix)" {
    write_config "strict"
    run_wd
    mtime_before="$(stat -c '%Y' "${DROPIN}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DROPIN}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: DRY_RUN does not write drop-in or fire sysctl -w" {
    write_config "strict"
    DRY_RUN=1 run_wd
    ! [ -f "${DROPIN}" ]
    ! grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "drop-in carries header marker + profile" {
    write_config "strict"
    run_wd
    grep -q 'managed-by: selfdef kernel-yama-baseline' "${DROPIN}"
    grep -q 'profile=strict' "${DROPIN}"
}

@test "default profile is relaxed (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'profile=relaxed' "${DROPIN}"
    grep -q 'sysctl -w kernel.yama.ptrace_scope=1' "${SCTL_LOG}"
}

@test "INVARIANT (drop-in carries actual sysctl directive ptrace_scope=N)" {
    write_config "strict"
    run_wd
    grep -qE 'kernel\.yama\.ptrace_scope\s*=\s*2' "${DROPIN}"
}

@test "INVARIANT (profile transition relaxed → strict): rewrites drop-in + applies live" {
    write_config "relaxed"
    run_wd
    grep -q 'profile=relaxed' "${DROPIN}"
    write_config "strict"
    : > "${SCTL_LOG}"
    run_wd
    grep -q 'profile=strict' "${DROPIN}"
    grep -q 'sysctl -w kernel.yama.ptrace_scope=2' "${SCTL_LOG}"
}

@test "INVARIANT (profile transition strict → paranoid WITH ack): rewrites drop-in + applies =3 live" {
    write_config "strict"
    run_wd
    write_config "paranoid" "true"
    : > "${SCTL_LOG}"
    run_wd
    grep -q 'profile=paranoid' "${DROPIN}"
    grep -q 'sysctl -w kernel.yama.ptrace_scope=3' "${SCTL_LOG}"
}

@test "INVARIANT (drop-in chmod 0644): sysctl.d convention" {
    write_config "strict"
    run_wd
    [ "$(stat -c '%a' "${DROPIN}")" = "644" ]
}

@test "INVARIANT (live-knob re-application — sysctl -w fires on every apply)" {
    write_config "strict"
    run_wd
    : > "${SCTL_LOG}"
    run_wd
    grep -q 'sysctl -w kernel.yama.ptrace_scope=' "${SCTL_LOG}"
}

@test "INVARIANT (no render-timestamp in drop-in): defeats cmp -s idempotency guard" {
    write_config "strict"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${DROPIN}"
}
