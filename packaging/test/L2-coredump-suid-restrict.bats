#!/usr/bin/env bats
# L2 functional suite for coredump-suid-restrict.
#
# coredump-suid-restrict blocks setuid-binary core dumps. By
# default, a setuid binary that crashes does NOT dump core
# (fs.suid_dumpable=0) — and that's because the dump contains
# the binary's effective-uid memory contents, including any
# secrets the setuid program loaded. Some misconfigured systems
# enable fs.suid_dumpable=1 or =2 for debugging; this module
# pins it back to 0.
#
# Profiles:
#   suid-only → fs.suid_dumpable=0 only (lets normal-user processes
#               still dump cores)
#   all-off   → suid-dumpable=0 PLUS /etc/security/limits.d/* with
#               `* hard core 0` (disables ALL coredumps, PAM
#               evaluated on next login)
#
# CRITICAL INVARIANT: profile downgrade all-off → suid-only
# REMOVES the limits.d file (no stale file from prior profile).
# Without this, the user could "downgrade" the profile but still
# have the all-off PAM restriction active — defeating the
# downgrade intent.
#
# Adds 2 env-var overrides for L2 testability. Live default
# unchanged.
#
# Run with: bats packaging/test/L2-coredump-suid-restrict.bats

WD="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/sysctl" <<'SCEOF'
#!/usr/bin/env bash
printf 'sysctl %s\n' "$*" >> "${SCTL_LOG}"
case "$1" in
    -n) printf '0\n' ;;
esac
exit 0
SCEOF
    chmod +x "${BIN}/sysctl"
    export SCTL_LOG="${TMP}/sysctl.log"
    : > "${SCTL_LOG}"
    CONF="${TMP}/coredump-suid-restrict.toml"
    SYSCTL_DROPIN="${TMP}/50-selfdef-suid-dumpable.conf"
    LIMITS_DROPIN="${TMP}/50-selfdef-coredump.conf"
    LIMITS_D="$(dirname "${LIMITS_DROPIN}")"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SCTL_LOG="${SCTL_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_COREDUMP_SUID_CONFIG="${CONF}" \
    SELFDEF_COREDUMP_SUID_SYSCTL_DROPIN="${SYSCTL_DROPIN}" \
    SELFDEF_COREDUMP_SUID_LIMITS_DROPIN="${LIMITS_DROPIN}" \
    SELFDEF_LIMITS_D="${LIMITS_D}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_COREDUMP_SUID_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_COREDUMP_SUID_CONFIG="${SELFDEF_COREDUMP_SUID_CONFIG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_COREDUMP_SUID_CONFIG="${CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be suid-only|all-off"* ]]
}

@test "suid-only profile installs sysctl drop-in + sysctl -w fs.suid_dumpable=0" {
    write_config "suid-only"
    run_wd
    [ -f "${SYSCTL_DROPIN}" ]
    grep -q 'sysctl -w fs.suid_dumpable=0' "${SCTL_LOG}"
    # No limits.d file from suid-only profile.
    ! [ -f "${LIMITS_DROPIN}" ]
}

@test "all-off profile installs BOTH sysctl + limits.d drop-ins" {
    write_config "all-off"
    run_wd
    [ -f "${SYSCTL_DROPIN}" ]
    [ -f "${LIMITS_DROPIN}" ]
    grep -q 'sysctl -w fs.suid_dumpable=0' "${SCTL_LOG}"
}

@test "INVARIANT: profile downgrade all-off → suid-only REMOVES stale limits.d file" {
    write_config "all-off"
    run_wd
    [ -f "${LIMITS_DROPIN}" ]
    # Downgrade.
    write_config "suid-only"
    run_wd
    ! [ -f "${LIMITS_DROPIN}" ]               # MUST be removed
    [ -f "${SYSCTL_DROPIN}" ]                 # sysctl drop-in retained
}

@test "INVARIANT: stale limits.d files NOT owned by selfdef are left alone" {
    write_config "suid-only"
    # Pre-existing limits.d file with someone else's header.
    printf '# managed-by: someone-else\n* hard core 0\n' > "${LIMITS_DROPIN}"
    run_wd
    # File still present — selfdef won't touch what it didn't create.
    [ -f "${LIMITS_DROPIN}" ]
    grep -q 'someone-else' "${LIMITS_DROPIN}"
}

@test "INVARIANT: DRY_RUN does not write either drop-in or fire sysctl" {
    write_config "all-off"
    DRY_RUN=1 run_wd
    ! [ -f "${SYSCTL_DROPIN}" ]
    ! [ -f "${LIMITS_DROPIN}" ]
    ! grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "drop-in carries header marker + profile (no timestamp — defeats cmp -s)" {
    write_config "suid-only"
    run_wd
    grep -q 'managed-by: selfdef coredump-suid-restrict' "${SYSCTL_DROPIN}"
    grep -q 'profile=suid-only' "${SYSCTL_DROPIN}"
    # Anti-timestamp invariant (2026-06-06 idempotency sweep).
    ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "${SYSCTL_DROPIN}"
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite drop-in (2026-06-06 idempotency fix)" {
    write_config "suid-only"
    run_wd
    mtime_before="$(stat -c '%Y' "${SYSCTL_DROPIN}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${SYSCTL_DROPIN}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "default profile is suid-only (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${SYSCTL_DROPIN}" ]
    ! [ -f "${LIMITS_DROPIN}" ]
}

@test "INVARIANT (profile upgrade suid-only → all-off): ADDS limits.d drop-in (reverse of test-104)" {
    write_config "suid-only"
    run_wd
    ! [ -f "${LIMITS_DROPIN}" ]
    write_config "all-off"
    run_wd
    [ -f "${LIMITS_DROPIN}" ]
}

@test "INVARIANT (sysctl drop-in carries fs.suid_dumpable=0 directive — the actual restriction)" {
    write_config "suid-only"
    run_wd
    grep -qE '^fs\.suid_dumpable\s*=\s*0' "${SYSCTL_DROPIN}"
}

@test "INVARIANT (all-off limits.d carries '* hard core 0' — PAM-evaluated restriction)" {
    write_config "all-off"
    run_wd
    grep -qE 'hard\s+core\s+0' "${LIMITS_DROPIN}"
}

@test "INVARIANT (sysctl drop-in chmod 0644 — sysctl.d convention)" {
    write_config "suid-only"
    run_wd
    [ "$(stat -c '%a' "${SYSCTL_DROPIN}")" = "644" ]
}

@test "INVARIANT (all-off limits.d drop-in chmod 0644 — security/limits.d convention)" {
    write_config "all-off"
    run_wd
    [ "$(stat -c '%a' "${LIMITS_DROPIN}")" = "644" ]
}

@test "INVARIANT (no render-timestamp in limits.d drop-in — defeats cmp -s on PAM file too)" {
    # The variant-A guard for the secondary drop-in. The sysctl drop-in
    # is covered above; the PAM-evaluated limits.d drop-in also lives
    # under the same cmp -s gate and must not carry a render-timestamp.
    write_config "all-off"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "${LIMITS_DROPIN}"
}

@test "INVARIANT (sysctl -w fires on every apply): the LIVE kernel knob must be set even when drop-in unchanged" {
    # If the sysctl drop-in is already on disk byte-identical, the
    # disk-write skips (mtime test) — BUT the LIVE kernel parameter
    # might still be wrong (operator could have done `sysctl -w
    # fs.suid_dumpable=1`). The script must still re-apply the LIVE
    # knob even on idempotent-disk path.
    write_config "suid-only"
    run_wd
    : > "${SCTL_LOG}"
    run_wd
    # Even with disk unchanged, sysctl -w fires for the live-knob.
    grep -q 'sysctl -w fs.suid_dumpable=0' "${SCTL_LOG}"
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates sysctl drop-in + fires sysctl -w)" {
    # Operator may rm the sysctl drop-in — apply must rebuild
    # and re-apply live so kernel state is restored.
    write_config "suid-only"
    run_wd
    [ -f "${SYSCTL_DROPIN}" ]
    rm -f "${SYSCTL_DROPIN}"
    : > "${SCTL_LOG}"
    run_wd
    [ -f "${SYSCTL_DROPIN}" ]
    grep -q 'sysctl -w fs.suid_dumpable=0' "${SCTL_LOG}"
}

@test "INVARIANT (re-arm after operator out-of-band deletion all-off: re-creates BOTH drop-ins)" {
    # all-off has 2 drop-ins (sysctl + limits.d). Both must be
    # re-armed on deletion.
    write_config "all-off"
    run_wd
    [ -f "${SYSCTL_DROPIN}" ]
    [ -f "${LIMITS_DROPIN}" ]
    rm -f "${SYSCTL_DROPIN}" "${LIMITS_DROPIN}"
    : > "${SCTL_LOG}"
    run_wd
    [ -f "${SYSCTL_DROPIN}" ]
    [ -f "${LIMITS_DROPIN}" ]
}

@test "INVARIANT (header-marker is first non-blank line — stale-cleanup head -1 discipline)" {
    write_config "suid-only"
    run_wd
    first_line="$(awk 'NF' "${SYSCTL_DROPIN}" | head -1)"
    [[ "${first_line}" == *"selfdef coredump-suid-restrict"* ]]
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "all-off"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"coredump-suid-restrict"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=all-off'* ]]
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # TOML; parser must tolerate without altering the profile-gated
    # behavior. all-off-with-noise still installs BOTH sysctl +
    # limits.d drop-ins.
    cat > "${CONF}" <<'TOMLEOF'
profile = "all-off"
operator_note = "all-off — disable ALL coredumps"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    [ -f "${SYSCTL_DROPIN}" ]
    [ -f "${LIMITS_DROPIN}" ]
}

@test "INVARIANT (asymmetric profile content: suid-only does NOT install limits.d — limits is all-off-only)" {
    # Sister to many other installer module's asymmetric-profile
    # INVARIANT across the brain (ssh-hardening AllowGroups,
    # selinux-baseline autorelabel, tmpfs-baseline /tmp-only). The
    # suid-only profile narrows to the suid-only-coredump axis (the
    # priv-elevated-process leak vector); the all-off profile widens
    # to ALL coredumps via the limits.d PAM-evaluated hard core 0
    # directive. If suid-only silently installed limits.d, it would
    # over-reach (operator's debugging of non-suid processes would
    # break unexpectedly). Locks the boundary: suid-only sysctl-
    # only, all-off both.
    write_config "suid-only"
    run_wd
    [ -f "${SYSCTL_DROPIN}" ]
    ! [ -f "${LIMITS_DROPIN}" ]
}

@test "INVARIANT (sysctl drop-in is sysctl.d-parseable: fs.suid_dumpable=0 format — boot-time persistence contract)" {
    # Sister to kernel-yama-baseline + aslr-baseline sysctl.d-
    # parseable INVARIANTs already locked. The drop-in lives at
    # /etc/sysctl.d/50-selfdef-coredump-suid.conf and is parsed
    # by systemd-sysctl.service at boot. The format MUST be
    # 'fs.suid_dumpable = 0' (or '=0' without space, both
    # sysctl.d-valid). A malformed line would silently fail at
    # boot — the runtime sysctl -w would set the value for
    # current boot but it would NOT persist across reboot,
    # leaving the host with degraded suid-coredump-restriction
    # on next boot.
    write_config "suid-only"
    run_wd
    [ -f "${SYSCTL_DROPIN}" ]
    grep -qE '^fs\.suid_dumpable[[:space:]]*=[[:space:]]*0$' "${SYSCTL_DROPIN}"
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO drop-in render AND NO sysctl -w fires when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing /etc/sysctl.d/50-selfdef-coredump-
    # suid.conf AND without firing sysctl -w fs.suid_dumpable=0.
    # A silent dry-run that committed would flip the live kernel
    # knob on a host where operator was investigating coredump
    # behavior (suid-binary debugging). Locks the dry-run-
    # preserves-state contract on the coredump-suid-restriction
    # substrate.
    write_config "suid-only"
    rm -f "${SYSCTL_DROPIN}"
    : > "${SCTL_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${SYSCTL_DROPIN}" ]
    ! grep -q 'sysctl -w fs.suid_dumpable' "${SCTL_LOG}"
}

@test "INVARIANT (drop-in is chmod 0644 — system-config convention)" {
    write_config "suid-only"
    run_wd
    [ -f "${SYSCTL_DROPIN}" ]
    [ "$(stat -c '%a' "${SYSCTL_DROPIN}")" = "644" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on coredump-suid-restrict
    # installer surface across sysctl + limits.d phases.
    write_config "suid-only"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"coredump-suid-restrict"')
    [ "${count}" = "1" ]
}
