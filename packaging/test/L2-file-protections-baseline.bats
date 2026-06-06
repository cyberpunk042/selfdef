#!/usr/bin/env bats
# L2 functional suite for file-protections-baseline.
#
# file-protections-baseline pins fs.protected_* sysctls. These
# kernel knobs block classic symlink/hardlink-attack vectors:
#   fs.protected_hardlinks = 1 → can't hardlink to files you don't
#                                own (blocks privesc via setuid-
#                                hardlinks-in-/tmp class)
#   fs.protected_symlinks  = 1 → block following symlinks in
#                                sticky world-writable dirs (blocks
#                                /tmp race attacks)
#   fs.protected_fifos     = 2 → block writing to FIFOs owned by
#                                others in world-writable dirs
#   fs.protected_regular   = 2 → block writing to regular files
#                                owned by others in world-writable
#                                dirs (the 2017 CVE-2017-7610-class
#                                race window)
#
# Profiles:
#   baseline → conservative (=1 where appropriate)
#   strict   → aggressive (=2 everywhere)
#
# Adds SELFDEF_FILEPROT_DROPIN env-var for L2 testability. Live
# default unchanged.
#
# Run with: bats packaging/test/L2-file-protections-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/apply.sh"

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
    CONF="${TMP}/file-protections-baseline.toml"
    DROPIN="${TMP}/50-selfdef-file-protections.conf"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SCTL_LOG="${SCTL_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_FILEPROT_CONFIG="${CONF}" \
    SELFDEF_FILEPROT_DROPIN="${DROPIN}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_FILEPROT_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_FILEPROT_CONFIG="${SELFDEF_FILEPROT_CONFIG}" \
        SELFDEF_FILEPROT_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_FILEPROT_CONFIG="${CONF}" \
        SELFDEF_FILEPROT_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be baseline|strict"* ]]
}

@test "baseline profile installs drop-in + applies sysctl -w per key" {
    write_config "baseline"
    run_wd
    [ -f "${DROPIN}" ]
    # The baseline sysctls fire.
    grep -q 'sysctl -w fs.protected_hardlinks=1' "${SCTL_LOG}"
    grep -q 'sysctl -w fs.protected_symlinks=1' "${SCTL_LOG}"
}

@test "strict profile installs the strict drop-in" {
    write_config "strict"
    run_wd
    [ -f "${DROPIN}" ]
    # Strict bumps the values higher.
    grep -q 'sysctl -w fs.protected_regular=2' "${SCTL_LOG}"
    grep -q 'sysctl -w fs.protected_fifos=2' "${SCTL_LOG}"
}

@test "drop-in carries header marker + profile + timestamp" {
    write_config "baseline"
    run_wd
    grep -q 'managed-by: selfdef file-protections-baseline' "${DROPIN}"
    grep -q 'profile=baseline' "${DROPIN}"
    grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z' "${DROPIN}"
}

@test "INVARIANT: DRY_RUN does not write drop-in or fire sysctl" {
    write_config "baseline"
    DRY_RUN=1 run_wd
    ! [ -f "${DROPIN}" ]
    ! grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "drop-in is chmod 0644" {
    write_config "baseline"
    run_wd
    [ "$(stat -c '%a' "${DROPIN}")" = "644" ]
}

@test "default profile is baseline (no profile key — safe default)" {
    : > "${CONF}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'profile=baseline' "${DROPIN}"
}

@test "drop-in content contains every protected_* key (baseline)" {
    write_config "baseline"
    run_wd
    grep -q 'fs.protected_hardlinks' "${DROPIN}"
    grep -q 'fs.protected_symlinks' "${DROPIN}"
    grep -q 'fs.protected_fifos' "${DROPIN}"
    grep -q 'fs.protected_regular' "${DROPIN}"
}
