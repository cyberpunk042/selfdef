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

@test "INVARIANT (drop-in re-arm after operator out-of-band deletion: re-creates drop-in + fires sysctl)" {
    write_config "off"
    run_wd
    [ -f "${DROPIN}" ]
    rm -f "${DROPIN}"
    : > "${SCTL_LOG}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -qE 'kernel\.sysrq[[:space:]]*=' "${DROPIN}"
    grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "INVARIANT (header marker first non-blank line — stale-cleanup head -1 grep)" {
    write_config "off"
    run_wd
    first_line="$(head -1 "${DROPIN}")"
    [ "${first_line}" = "# managed-by: selfdef kernel-sysrq-restrict" ]
}

@test "INVARIANT (sysctl mechanism: -w flag for surgical single-key application — NOT -p path)" {
    # -w writes the live kernel value surgically.
    # -p would reload entire sysctl.d directory which would side-
    # effect other modules. Lock the choice.
    write_config "off"
    run_wd
    grep -qE 'sysctl -w' "${SCTL_LOG}"
    ! grep -qE 'sysctl -p' "${SCTL_LOG}"
}

@test "INVARIANT (emit_status JSON: status=ok + profile surfaced for operator dashboard)" {
    write_config "safe-subset"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"kernel-sysrq-restrict"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=safe-subset'* ]]
}

@test "INVARIANT (filename follows 50-selfdef-* convention — tracking + uninstall identification)" {
    # Sister to many other modules' filename-convention INVARIANT.
    write_config "off"
    run_wd
    case "${DROPIN}" in
        */50-selfdef-*.conf) : ;;
        *) fail "drop-in filename must follow 50-selfdef-*.conf pattern" ;;
    esac
}

@test "INVARIANT (drop-in is sysctl-parseable: each non-comment line matches key=value shape)" {
    # The drop-in is sourced by sysctl --system. Every non-comment
    # non-blank line MUST match the sysctl key=value grammar.
    # Sister to file-protections-baseline + sysctl-network-baseline
    # sysctl-parseable INVARIANT.
    write_config "safe-subset"
    run_wd
    awk '/^[[:space:]]*#/ || /^[[:space:]]*$/ {next} /^[a-zA-Z_][a-zA-Z0-9_.]*[[:space:]]*=[[:space:]]*[0-9]+/ {next} {bad=1; print "malformed: " $0} END{exit bad?1:0}' "${DROPIN}"
}

@test "INVARIANT (profile-rank monotonic: off (0) ≤ safe-subset (132 = sync+reboot) ≤ full (1 means ALL — distinct mode)) — locks bitmask values)" {
    # Lock the THREE specific bitmask values for the THREE
    # profiles. Operator can dashboard-verify the active value
    # against expectations. A regression that swaps values
    # would change the security posture silently.
    write_config "off"
    run_wd
    grep -qE 'kernel\.sysrq\s*=\s*0' "${DROPIN}"
    write_config "safe-subset"
    run_wd
    grep -qE 'kernel\.sysrq\s*=\s*132' "${DROPIN}"
    write_config "full"
    run_wd
    grep -qE 'kernel\.sysrq\s*=\s*1' "${DROPIN}"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # kernel-sysrq-restrict TOML; parser must tolerate without
    # altering the profile-gated behavior. off-with-noise still
    # installs the kernel.sysrq=0 drop-in (the sysrq full-disable
    # — closes the physical-console attack surface that lets
    # anyone with keyboard access send unauthenticated kernel
    # commands).
    cat > "${CONF}" <<'TOMLEOF'
profile = "off"
operator_note = "sysrq = physical-console unauthenticated kernel cmd surface"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    [ -f "${DROPIN}" ]
    grep -qE 'kernel\.sysrq\s*=\s*0' "${DROPIN}"
}
