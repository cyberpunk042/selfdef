#!/usr/bin/env bats
# L2 functional suite for umask-baseline.
#
# umask-baseline installs umask defaults via TWO drop-ins:
#   /etc/profile.d/50-selfdef-umask.sh    — interactive shells
#   /etc/login.defs.d/50-selfdef-umask.conf — PAM/login sessions
#
# Default umask 022 (world-readable) on a multi-user system means
# every file a user creates is readable by every OTHER user. On
# a sovereign endpoint that's a lateral-disclosure surface.
# Profiles tighten:
#   group  → 027 (group + world unreadable)
#   strict → 077 (group + world unreadable AND unwritable)
#
# CRITICAL INVARIANTS:
#   - Both drop-ins install per profile (different content per
#     profile — strict has tighter umask).
#   - Idempotent: byte-identical re-install is a no-op.
#   - DRY_RUN protects both drop-ins.
#
# Uses SELFDEF_PROFILE_D + SELFDEF_LOGIN_DEFS_D env-vars (already
# present).
#
# Run with: bats packaging/test/L2-umask-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    CONF="${TMP}/umask-baseline.toml"
    PROFILE_D="${TMP}/profile.d"
    LOGIN_DEFS_D="${TMP}/login.defs.d"
    mkdir -p "${PROFILE_D}" "${LOGIN_DEFS_D}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_UMASK_CONFIG="${CONF}" \
    SELFDEF_PROFILE_D="${PROFILE_D}" \
    SELFDEF_LOGIN_DEFS_D="${LOGIN_DEFS_D}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_UMASK_CONFIG="${TMP}/missing.toml"
    run env \
        SELFDEF_UMASK_CONFIG="${SELFDEF_UMASK_CONFIG}" \
        SELFDEF_PROFILE_D="${PROFILE_D}" \
        SELFDEF_LOGIN_DEFS_D="${LOGIN_DEFS_D}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env \
        SELFDEF_UMASK_CONFIG="${CONF}" \
        SELFDEF_PROFILE_D="${PROFILE_D}" \
        SELFDEF_LOGIN_DEFS_D="${LOGIN_DEFS_D}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be group|strict"* ]]
}

@test "group profile installs BOTH drop-ins with group-profile content" {
    write_config "group"
    run_wd
    [ -f "${PROFILE_D}/50-selfdef-umask.sh" ]
    [ -f "${LOGIN_DEFS_D}/50-selfdef-umask.conf" ]
    # Both drop-ins match the group-* source content.
    cmp -s modules/umask-baseline/configs/group-profile.sh "${PROFILE_D}/50-selfdef-umask.sh"
    cmp -s modules/umask-baseline/configs/group-login.conf "${LOGIN_DEFS_D}/50-selfdef-umask.conf"
}

@test "strict profile installs BOTH drop-ins with strict-profile content" {
    write_config "strict"
    run_wd
    cmp -s modules/umask-baseline/configs/strict-profile.sh "${PROFILE_D}/50-selfdef-umask.sh"
    cmp -s modules/umask-baseline/configs/strict-login.conf "${LOGIN_DEFS_D}/50-selfdef-umask.conf"
}

@test "INVARIANT: profile change group → strict replaces BOTH drop-ins" {
    write_config "group"
    run_wd
    sha_g_profile="$(sha256sum "${PROFILE_D}/50-selfdef-umask.sh" | awk '{print $1}')"
    sha_g_login="$(sha256sum "${LOGIN_DEFS_D}/50-selfdef-umask.conf" | awk '{print $1}')"
    write_config "strict"
    run_wd
    sha_s_profile="$(sha256sum "${PROFILE_D}/50-selfdef-umask.sh" | awk '{print $1}')"
    sha_s_login="$(sha256sum "${LOGIN_DEFS_D}/50-selfdef-umask.conf" | awk '{print $1}')"
    # Both drop-ins changed.
    [ "${sha_g_profile}" != "${sha_s_profile}" ]
    [ "${sha_g_login}" != "${sha_s_login}" ]
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT bump mtime" {
    write_config "group"
    run_wd
    mtime_before="$(stat -c '%Y' "${PROFILE_D}/50-selfdef-umask.sh")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${PROFILE_D}/50-selfdef-umask.sh")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "drop-ins are chmod 0644" {
    write_config "group"
    run_wd
    [ "$(stat -c '%a' "${PROFILE_D}/50-selfdef-umask.sh")" = "644" ]
    [ "$(stat -c '%a' "${LOGIN_DEFS_D}/50-selfdef-umask.conf")" = "644" ]
}

@test "INVARIANT: DRY_RUN does not write either drop-in" {
    write_config "group"
    DRY_RUN=1 run_wd
    ! [ -f "${PROFILE_D}/50-selfdef-umask.sh" ]
    ! [ -f "${LOGIN_DEFS_D}/50-selfdef-umask.conf" ]
}

@test "default profile is group (no profile key)" {
    : > "${CONF}"
    run_wd
    cmp -s modules/umask-baseline/configs/group-profile.sh "${PROFILE_D}/50-selfdef-umask.sh"
}

@test "INVARIANT (group profile umask value): drop-in sets umask 0027 exactly" {
    write_config "group"
    run_wd
    grep -qE 'umask +0027' "${PROFILE_D}/50-selfdef-umask.sh"
}

@test "INVARIANT (strict profile umask value): drop-in sets umask 0077 exactly" {
    write_config "strict"
    run_wd
    grep -qE 'umask +0077' "${PROFILE_D}/50-selfdef-umask.sh"
}

@test "INVARIANT (group profile login.defs UMASK directive): correct format" {
    write_config "group"
    run_wd
    grep -qE 'UMASK[[:space:]]+0?27' "${LOGIN_DEFS_D}/50-selfdef-umask.conf"
}

@test "INVARIANT (strict profile login.defs UMASK directive): correct format" {
    write_config "strict"
    run_wd
    grep -qE 'UMASK[[:space:]]+0?77' "${LOGIN_DEFS_D}/50-selfdef-umask.conf"
}

@test "INVARIANT (profile downgrade strict → group): rewrites BOTH drop-ins with looser umask" {
    write_config "strict"
    run_wd
    grep -qE 'umask +0077' "${PROFILE_D}/50-selfdef-umask.sh"
    write_config "group"
    run_wd
    grep -qE 'umask +0027' "${PROFILE_D}/50-selfdef-umask.sh"
    ! grep -qE 'umask +0077' "${PROFILE_D}/50-selfdef-umask.sh"
}

@test "INVARIANT (no render-timestamp in either drop-in): defeats cmp -s idempotency guard" {
    write_config "group"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${PROFILE_D}/50-selfdef-umask.sh"
    ! grep -qE '^# Generated [0-9]{4}-' "${LOGIN_DEFS_D}/50-selfdef-umask.conf"
}
