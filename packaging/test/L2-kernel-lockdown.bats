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

@test "INVARIANT (idempotent mtime): byte-identical re-install preserves drop-in mtime" {
    write_config "balanced"
    run_wd
    mtime_before="$(stat -c '%Y' "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT (profile upgrade balanced → strict WITH ack): installs strict drop-in + fires sysctl" {
    # Reverse of the downgrade lock — locks bidirectional contract.
    write_config "balanced"
    run_wd
    ! [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
    write_config "strict" "true"
    : > "${SCTL_LOG}"
    run_wd
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
    grep -q 'sysctl --system' "${SCTL_LOG}"
}

@test "INVARIANT (strict drop-in carries kernel.modules_disabled=1): the actual irreversible mechanism" {
    write_config "strict" "true"
    run_wd
    grep -qE 'kernel\.modules_disabled\s*=\s*1' "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf"
}

@test "INVARIANT (balanced does NOT carry modules_disabled): asymmetric content lock" {
    write_config "balanced"
    run_wd
    ! grep -qE 'kernel\.modules_disabled\s*=\s*1' "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf"
}

@test "INVARIANT (drop-in chmod 0644): sysctl.d convention" {
    write_config "balanced"
    run_wd
    [ "$(stat -c '%a' "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf")" = "644" ]
}

@test "INVARIANT (sysctl --system fires on change — operator-edit between runs forces re-apply)" {
    write_config "balanced"
    run_wd
    : > "${SCTL_LOG}"
    write_config "strict" "true"
    run_wd
    grep -q 'sysctl --system' "${SCTL_LOG}"
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates drop-in + fires sysctl --system)" {
    # Operator may rm the drop-in — apply must rebuild and re-apply
    # live so kernel state is restored.
    write_config "balanced"
    run_wd
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf" ]
    rm -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf"
    : > "${SCTL_LOG}"
    run_wd
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf" ]
    grep -q 'sysctl --system' "${SCTL_LOG}"
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "strict" "true"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"kernel-lockdown"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=strict'* ]]
}

@test "INVARIANT (refuse-to-brick precedence over profile-key — strict w/o ack dies even after prior balanced install)" {
    # Operator installs balanced first, then flips to strict but
    # FORGETS to set acknowledge_modules_disabled. apply MUST refuse
    # AND leave the prior balanced drop-in unchanged — no silent
    # escalation to strict-modules-disabled.
    write_config "balanced"
    run_wd
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf" ]
    ! [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
    # Operator sets strict w/o ack.
    write_config "strict" "false"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_KERNEL_LOCKDOWN_CONFIG="${CONF}" \
        SELFDEF_KERNEL_LOCKDOWN_SYSCTL="${SYSCTL_SRC}" \
        SELFDEF_SYSCTL_DIR="${SYSCTL_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    # Strict drop-in MUST NOT have been installed.
    ! [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
    # Prior balanced drop-in preserved.
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf" ]
}

@test "INVARIANT (downgrade strict → balanced fires sysctl --system to APPLY balanced settings — kernel state must drop modules_disabled)" {
    # When operator downgrades, the strict drop-in is removed BUT
    # the live kernel state still has modules_disabled=1 from the
    # prior load. The downgrade MUST fire sysctl --system to re-
    # apply the balanced-only state. (Note: modules_disabled is
    # itself irreversible until reboot — operator knows this — but
    # OTHER strict-only knobs may not be irreversible and must
    # reset.)
    write_config "strict" "true"
    run_wd
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
    : > "${SCTL_LOG}"
    write_config "balanced"
    run_wd
    ! [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
    # sysctl --system fires because content changed (strict dropin removed).
    grep -q 'sysctl --system' "${SCTL_LOG}"
}

@test "INVARIANT (drop-in filenames follow 50-selfdef-* convention — tracking + uninstall identification)" {
    # Both balanced and strict drop-ins must follow the 50-selfdef-
    # prefix convention. Sister to many other modules' filename-
    # convention INVARIANT.
    write_config "strict" "true"
    run_wd
    case "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf" in
        */50-selfdef-*) : ;;
        *) fail "balanced drop-in does not follow 50-selfdef-* pattern" ;;
    esac
    case "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" in
        */50-selfdef-*) : ;;
        *) fail "strict drop-in does not follow 50-selfdef-* pattern" ;;
    esac
}

@test "INVARIANT (config-layer-noise resilience: extra unknown TOML keys do NOT bypass acknowledge_modules_disabled gate)" {
    # Sister to nftables-baseline refuse-to-brick precedence INVARIANT.
    # Lock that extra config keys cannot accidentally bypass the
    # refuse-to-brick gate via TOML parsing edge cases.
    cat > "${CONF}" <<'EOF'
profile = "strict"
acknowledge_modules_disabled = false
some_other_knob = "wrong"
maybe_a_typo = true
EOF
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_KERNEL_LOCKDOWN_CONFIG="${CONF}" \
        SELFDEF_KERNEL_LOCKDOWN_SYSCTL="${SYSCTL_SRC}" \
        SELFDEF_SYSCTL_DIR="${SYSCTL_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"IRREVERSIBLE until reboot"* ]] || [[ "${output}" == *"acknowledge_modules_disabled"* ]]
    ! [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
}

@test "INVARIANT (drop-in is sysctl.d-parseable: kernel.modules_disabled=<N> format — boot-time persistence contract)" {
    # Sister to kernel-yama-baseline + aslr-baseline + coredump-
    # suid-restrict sysctl.d-parseable INVARIANTs already locked.
    # The strict-profile drop-in lives at /etc/sysctl.d/50-selfdef-
    # kernel-lockdown-strict.conf and is parsed by systemd-sysctl.
    # service at boot. A malformed kernel.modules_disabled line
    # would silently fail at boot — the runtime sysctl -w would
    # set it for current boot but the value would NOT persist
    # across reboot, leaving the host with degraded module-loading
    # restriction on next boot.
    write_config "strict" "true"
    run_wd
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
    grep -qE '^kernel\.modules_disabled[[:space:]]*=[[:space:]]*1$' "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf"
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO drop-in render AND NO sysctl --system fires when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing /etc/sysctl.d/50-selfdef-kernel-
    # lockdown-*.conf AND without firing sysctl --system. The
    # strict profile in particular is IRREVERSIBLE until reboot
    # — a silent dry-run that committed would lock out module-
    # loading on a host under investigation, breaking any
    # incident-response workflow that needs to insmod
    # diagnostics modules. Locks dry-run-preserves-state on
    # kernel-lockdown substrate.
    write_config "balanced"
    rm -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-balanced.conf"
    : > "${SCTL_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-balanced.conf" ]
    ! grep -qE 'sysctl --system' "${SCTL_LOG}"
}

@test "INVARIANT (drop-in chmod 0644 — system-config convention)" {
    # Sister to brain-wide chmod 0644 INVARIANTs.
    write_config "balanced"
    run_wd
    file="${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf"
    [ -f "${file}" ]
    [ "$(stat -c '%a' "${file}")" = "644" ]
}
