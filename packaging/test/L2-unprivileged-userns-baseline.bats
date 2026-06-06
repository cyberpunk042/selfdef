#!/usr/bin/env bats
# L2 functional suite for unprivileged-userns-baseline.
#
# unprivileged-userns-baseline pins kernel.unprivileged_userns_clone.
# This sysctl is the gate for rootless containers (podman/docker),
# bubblewrap-based sandboxes (Flatpak), and a few CVE-prone kernel
# paths. Two profiles:
#   allow → kernel.unprivileged_userns_clone=1 (preserves rootless
#           containers + Flatpak + bubblewrap; mainstream Debian
#           default since bookworm)
#   deny  → kernel.unprivileged_userns_clone=0 (kills rootless
#           podman/docker, bubblewrap, Flatpak — kernel-attack
#           surface reduction)
#
# CRITICAL INVARIANT: deny is destructive (breaks rootless
# containers + Flatpak). The script requires
# acknowledge_no_rootless=true in the config or REFUSES TO APPLY.
# Refuse-to-brick guard parallel to kernel-yama paranoid +
# kernel-lockdown strict.
#
# Adds SELFDEF_USERNS_DROPIN env-var (added 2026-06-06) for L2
# testability. Live default unchanged.
#
# Run with: bats packaging/test/L2-unprivileged-userns-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/sysctl" <<'SCEOF'
#!/usr/bin/env bash
printf 'sysctl %s\n' "$*" >> "${SCTL_LOG}"
case "$1" in
    -n) printf '%s\n' "${LIVE_USERNS:-1}" ;;
esac
exit 0
SCEOF
    chmod +x "${BIN}/sysctl"
    export SCTL_LOG="${TMP}/sysctl.log"
    : > "${SCTL_LOG}"
    CONF="${TMP}/unprivileged-userns-baseline.toml"
    DROPIN="${TMP}/50-selfdef-userns.conf"
}

teardown() { rm -rf "${TMP}"; }

# write_config <profile> [ack_no_rootless]
write_config() {
    local profile="$1" ack="${2:-false}"
    printf 'profile = "%s"\n' "${profile}" > "${CONF}"
    printf 'acknowledge_no_rootless = %s\n' "${ack}" >> "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SCTL_LOG="${SCTL_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_USERNS_CONFIG="${CONF}" \
    SELFDEF_USERNS_DROPIN="${DROPIN}" \
    LIVE_USERNS="${LIVE_USERNS:-1}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_USERNS_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_USERNS_CONFIG="${SELFDEF_USERNS_CONFIG}" \
        SELFDEF_USERNS_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_USERNS_CONFIG="${CONF}" \
        SELFDEF_USERNS_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be allow|deny"* ]]
}

@test "INVARIANT: deny without acknowledgment → die (refuse-to-brick guard for rootless containers + Flatpak)" {
    write_config "deny" "false"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_USERNS_CONFIG="${CONF}" \
        SELFDEF_USERNS_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"rootless"* ]]
    ! [ -f "${DROPIN}" ]
}

@test "allow profile → sysctl -w kernel.unprivileged_userns_clone=1 + writes dropin" {
    write_config "allow"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'profile=allow' "${DROPIN}"
    grep -q 'sysctl -w kernel.unprivileged_userns_clone=1' "${SCTL_LOG}"
}

@test "deny profile WITH acknowledgment → sysctl -w kernel.unprivileged_userns_clone=0" {
    write_config "deny" "true"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'profile=deny' "${DROPIN}"
    grep -q 'sysctl -w kernel.unprivileged_userns_clone=0' "${SCTL_LOG}"
}

@test "drop-in carries header marker + profile + source content (no timestamp — defeats cmp -s)" {
    write_config "allow"
    run_wd
    grep -q 'managed-by: selfdef unprivileged-userns-baseline' "${DROPIN}"
    grep -q 'profile=allow' "${DROPIN}"
    # Anti-timestamp invariant (2026-06-06 sweep).
    ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "${DROPIN}"
}

@test "drop-in is chmod 0644 (system-config convention)" {
    write_config "allow"
    run_wd
    [ "$(stat -c '%a' "${DROPIN}")" = "644" ]
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite drop-in (2026-06-06 idempotency fix)" {
    write_config "allow"
    run_wd
    [ -f "${DROPIN}" ]
    mtime_before="$(stat -c '%Y' "${DROPIN}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DROPIN}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: DRY_RUN does not write drop-in or fire sysctl -w" {
    write_config "allow"
    DRY_RUN=1 run_wd
    ! [ -f "${DROPIN}" ]
    ! grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "default profile is allow (no profile key — preserves rootless containers)" {
    : > "${CONF}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'profile=allow' "${DROPIN}"
    grep -q 'sysctl -w kernel.unprivileged_userns_clone=1' "${SCTL_LOG}"
}

@test "INVARIANT (profile transition allow → deny WITH ack): rewrites drop-in + applies sysctl 0" {
    write_config "allow"
    run_wd
    grep -q 'profile=allow' "${DROPIN}"
    write_config "deny" "true"
    : > "${SCTL_LOG}"
    run_wd
    grep -q 'profile=deny' "${DROPIN}"
    grep -q 'sysctl -w kernel.unprivileged_userns_clone=0' "${SCTL_LOG}"
}

@test "INVARIANT (profile transition deny → allow): rewrites drop-in back + applies sysctl 1" {
    write_config "deny" "true"
    run_wd
    grep -q 'profile=deny' "${DROPIN}"
    write_config "allow"
    : > "${SCTL_LOG}"
    run_wd
    grep -q 'profile=allow' "${DROPIN}"
    grep -q 'sysctl -w kernel.unprivileged_userns_clone=1' "${SCTL_LOG}"
}

@test "INVARIANT (drop-in carries the actual sysctl directive): allow → kernel.unprivileged_userns_clone=1" {
    write_config "allow"
    run_wd
    grep -qE 'kernel\.unprivileged_userns_clone\s*=\s*1' "${DROPIN}"
}

@test "INVARIANT (drop-in carries the actual sysctl directive): deny → kernel.unprivileged_userns_clone=0" {
    write_config "deny" "true"
    run_wd
    grep -qE 'kernel\.unprivileged_userns_clone\s*=\s*0' "${DROPIN}"
}

@test "INVARIANT (live-knob re-application — sysctl -w fires on every apply even when drop-in unchanged)" {
    write_config "allow"
    run_wd
    : > "${SCTL_LOG}"
    run_wd
    grep -q 'sysctl -w kernel.unprivileged_userns_clone=' "${SCTL_LOG}"
}

@test "INVARIANT (drop-in filename selfdef-* pattern): tracking + uninstall identification" {
    write_config "allow"
    run_wd
    case "${DROPIN}" in
        */50-selfdef-*.conf) : ;;
        *) fail "drop-in filename must follow 50-selfdef-*.conf pattern" ;;
    esac
}
