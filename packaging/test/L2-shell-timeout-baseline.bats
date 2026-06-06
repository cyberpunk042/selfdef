#!/usr/bin/env bats
# L2 functional suite for shell-timeout-baseline.
#
# shell-timeout-baseline installs /etc/profile.d/50-selfdef-
# tmout.sh which sets TMOUT (bash/sh inactivity timeout) so idle
# shell sessions auto-logout. Critical against the
# unlocked-terminal-walked-away attack vector (operator leaves
# the laptop in a coffee shop with an SSH session open;
# attacker sits down at the screen).
#
# Profiles:
#   standard → TMOUT=900  (15 minutes)
#   strict   → TMOUT=300  (5 minutes)
#
# CRITICAL INVARIANTS this suite locks:
#   - Idempotent: byte-identical re-install does NOT rewrite the
#     drop-in (the 2026-06-06 fix adds cmp -s + drops the
#     render-timestamp that defeated it).
#   - Drop-in starts with `#!/bin/sh` shebang (profile.d files
#     are sourced by every login shell — the shebang is a
#     readability marker, not strictly needed).
#   - Profile change rewrites the drop-in with the new TMOUT.
#   - DRY_RUN protects drop-in install.
#
# Adds 2 env-var overrides (SELFDEF_TMOUT_PROFILE_D +
# SELFDEF_TMOUT_DROPIN) for L2 testability. Live default
# behavior unchanged.
#
# Run with: bats packaging/test/L2-shell-timeout-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    CONF="${TMP}/shell-timeout-baseline.toml"
    PROFILE_D="${TMP}/profile.d"
    DROPIN="${PROFILE_D}/50-selfdef-tmout.sh"
    mkdir -p "${PROFILE_D}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_TMOUT_CONFIG="${CONF}" \
    SELFDEF_TMOUT_PROFILE_D="${PROFILE_D}" \
    SELFDEF_TMOUT_DROPIN="${DROPIN}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_TMOUT_CONFIG="${TMP}/missing.toml"
    run env \
        SELFDEF_TMOUT_CONFIG="${SELFDEF_TMOUT_CONFIG}" \
        SELFDEF_TMOUT_PROFILE_D="${PROFILE_D}" \
        SELFDEF_TMOUT_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env \
        SELFDEF_TMOUT_CONFIG="${CONF}" \
        SELFDEF_TMOUT_PROFILE_D="${PROFILE_D}" \
        SELFDEF_TMOUT_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be standard|strict"* ]]
}

@test "standard profile installs drop-in with TMOUT=900 (15 min)" {
    write_config "standard"
    run_wd
    [ -f "${DROPIN}" ]
    head -1 "${DROPIN}" | grep -qF '#!/bin/sh'
    grep -q 'managed-by: selfdef shell-timeout-baseline' "${DROPIN}"
    grep -q 'profile=standard' "${DROPIN}"
    grep -q 'TMOUT' "${DROPIN}"
}

@test "strict profile installs drop-in with shorter TMOUT" {
    write_config "strict"
    run_wd
    grep -q 'profile=strict' "${DROPIN}"
}

@test "drop-in is chmod 0644 (profile.d convention)" {
    write_config "standard"
    run_wd
    [ "$(stat -c '%a' "${DROPIN}")" = "644" ]
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite drop-in (timestamp removed 2026-06-06)" {
    write_config "standard"
    run_wd
    mtime_before="$(stat -c '%Y' "${DROPIN}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DROPIN}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: profile change standard → strict rewrites drop-in (content differs)" {
    write_config "standard"
    run_wd
    sha_before="$(sha256sum "${DROPIN}" | awk '{print $1}')"
    write_config "strict"
    run_wd
    sha_after="$(sha256sum "${DROPIN}" | awk '{print $1}')"
    [ "${sha_before}" != "${sha_after}" ]
    grep -q 'profile=strict' "${DROPIN}"
}

@test "INVARIANT: DRY_RUN does not write drop-in" {
    write_config "standard"
    DRY_RUN=1 run_wd
    ! [ -f "${DROPIN}" ]
}

@test "default profile is standard (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'profile=standard' "${DROPIN}"
}

@test "INVARIANT (standard TMOUT value): drop-in carries TMOUT=900 exactly" {
    write_config "standard"
    run_wd
    grep -qE 'TMOUT=900' "${DROPIN}"
}

@test "INVARIANT (strict TMOUT value): drop-in carries TMOUT=300 exactly (5 min — locked from drift)" {
    write_config "strict"
    run_wd
    grep -qE 'TMOUT=300' "${DROPIN}"
}

@test "INVARIANT (readonly TMOUT — user cannot unset): drop-in marks TMOUT readonly" {
    # If TMOUT is not readonly, the attacker (or user-by-accident) can
    # do `unset TMOUT` and defeat the whole control. Locking it readonly
    # is the canonical bash-hardening pattern.
    write_config "standard"
    run_wd
    grep -qE '^(readonly|declare -r) TMOUT' "${DROPIN}" || \
    grep -qE 'readonly +TMOUT' "${DROPIN}"
}

@test "INVARIANT (export TMOUT): drop-in exports TMOUT so child shells inherit it" {
    write_config "standard"
    run_wd
    # Conditional inside case block; assert export TMOUT anywhere.
    grep -qE 'export +TMOUT' "${DROPIN}"
}

@test "INVARIANT (profile downgrade strict → standard): rewrites with longer TMOUT" {
    write_config "strict"
    run_wd
    grep -qE 'TMOUT=300' "${DROPIN}"
    write_config "standard"
    run_wd
    grep -qE 'TMOUT=900' "${DROPIN}"
    ! grep -qE 'TMOUT=300' "${DROPIN}"
}

@test "INVARIANT (no render-timestamp in drop-in): defeats cmp -s idempotency guard" {
    write_config "standard"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${DROPIN}"
}
