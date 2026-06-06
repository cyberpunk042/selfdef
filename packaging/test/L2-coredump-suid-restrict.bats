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

@test "drop-in carries header marker + timestamp" {
    write_config "suid-only"
    run_wd
    grep -q 'managed-by: selfdef coredump-suid-restrict' "${SYSCTL_DROPIN}"
    grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z' "${SYSCTL_DROPIN}"
}

@test "default profile is suid-only (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${SYSCTL_DROPIN}" ]
    ! [ -f "${LIMITS_DROPIN}" ]
}
