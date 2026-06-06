#!/usr/bin/env bats
# L2 functional suite for login-defs-baseline.
#
# login-defs-baseline tightens password policy defaults via
# /etc/login.defs (PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE,
# ENCRYPT_METHOD). Profiles:
#   standard → 90-day max, sha512 encryption
#   strict   → 60-day max + history + ucredit/lcredit
#
# Writes via TWO mechanisms for cross-distro coverage:
#   1. /etc/login.defs.d/50-selfdef-login-defs.conf (Debian 11+,
#      RHEL 9+, modern distros — primary path)
#   2. /etc/login.defs marker-fenced append block (legacy distros
#      that don't read .d directories)
#
# CRITICAL INVARIANTS this suite locks:
#   - Marker-fenced legacy append is idempotent: re-running
#     REPLACES the prior block (the sed -i strip-and-reappend
#     pattern) rather than appending duplicates.
#   - Pre-existing operator content in /etc/login.defs (NON-
#     marker-fenced) is PRESERVED.
#   - Drop-in carries header marker for stale-file identification.
#
# Adds SELFDEF_LOGIN_DEFS_D + SELFDEF_LEGACY_LOGIN_DEFS env-vars
# (added 2026-06-06) for L2 testability.
#
# Run with: bats packaging/test/L2-login-defs-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    CONF="${TMP}/login-defs-baseline.toml"
    LOGIN_DEFS_D="${TMP}/login.defs.d"
    LEGACY_LOGIN_DEFS="${TMP}/login.defs"
    DROPIN="${LOGIN_DEFS_D}/50-selfdef-login-defs.conf"
    mkdir -p "${LOGIN_DEFS_D}"
    # Pre-existing /etc/login.defs with operator content.
    cat > "${LEGACY_LOGIN_DEFS}" <<'LDEOF'
# Operator-authored content (NOT marker-fenced)
UMASK 022
MAIL_DIR /var/mail
LDEOF
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_LOGINDEFS_CONFIG="${CONF}" \
    SELFDEF_LOGIN_DEFS_D="${LOGIN_DEFS_D}" \
    SELFDEF_LEGACY_LOGIN_DEFS="${LEGACY_LOGIN_DEFS}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_LOGINDEFS_CONFIG="${TMP}/missing.toml"
    run env \
        SELFDEF_LOGINDEFS_CONFIG="${SELFDEF_LOGINDEFS_CONFIG}" \
        SELFDEF_LOGIN_DEFS_D="${LOGIN_DEFS_D}" \
        SELFDEF_LEGACY_LOGIN_DEFS="${LEGACY_LOGIN_DEFS}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env \
        SELFDEF_LOGINDEFS_CONFIG="${CONF}" \
        SELFDEF_LOGIN_DEFS_D="${LOGIN_DEFS_D}" \
        SELFDEF_LEGACY_LOGIN_DEFS="${LEGACY_LOGIN_DEFS}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be standard|strict"* ]]
}

@test "standard profile writes drop-in + legacy fallback" {
    write_config "standard"
    run_wd
    [ -f "${DROPIN}" ]
    # Header marker in drop-in.
    grep -q 'managed-by: selfdef login-defs-baseline' "${DROPIN}"
    # Legacy fallback has marker-fenced block.
    grep -q 'managed-by: selfdef login-defs-baseline' "${LEGACY_LOGIN_DEFS}"
    grep -q '# end-selfdef login-defs-baseline' "${LEGACY_LOGIN_DEFS}"
}

@test "strict profile installs the strict drop-in content" {
    write_config "strict"
    run_wd
    [ -f "${DROPIN}" ]
    cmp_check_strict() {
        # Drop-in body (without our 2 header lines) matches the
        # strict source file.
        sed '1,2d' "${DROPIN}" | cmp -s - modules/login-defs-baseline/configs/strict.conf
    }
    cmp_check_strict
}

@test "INVARIANT: operator content in /etc/login.defs is PRESERVED (non-marker-fenced)" {
    write_config "standard"
    run_wd
    # Operator's UMASK + MAIL_DIR must survive.
    grep -q '^UMASK 022$' "${LEGACY_LOGIN_DEFS}"
    grep -q '^MAIL_DIR /var/mail$' "${LEGACY_LOGIN_DEFS}"
}

@test "INVARIANT: idempotent legacy append — re-run REPLACES prior block, doesn't duplicate" {
    write_config "standard"
    run_wd
    sha_before="$(sha256sum "${LEGACY_LOGIN_DEFS}" | awk '{print $1}')"
    n_markers_before="$(grep -c 'managed-by: selfdef login-defs-baseline' "${LEGACY_LOGIN_DEFS}")"
    run_wd
    sha_after="$(sha256sum "${LEGACY_LOGIN_DEFS}" | awk '{print $1}')"
    n_markers_after="$(grep -c 'managed-by: selfdef login-defs-baseline' "${LEGACY_LOGIN_DEFS}")"
    # Exactly one marker block (no duplication).
    [ "${n_markers_before}" = "1" ]
    [ "${n_markers_after}" = "1" ]
    # Legacy content unchanged byte-for-byte after re-run.
    [ "${sha_before}" = "${sha_after}" ]
}

@test "INVARIANT: profile change standard → strict replaces legacy block (content differs)" {
    write_config "standard"
    run_wd
    standard_block_sha="$(sed -n '/managed-by: selfdef/,/end-selfdef/p' "${LEGACY_LOGIN_DEFS}" | sha256sum | awk '{print $1}')"
    write_config "strict"
    run_wd
    strict_block_sha="$(sed -n '/managed-by: selfdef/,/end-selfdef/p' "${LEGACY_LOGIN_DEFS}" | sha256sum | awk '{print $1}')"
    [ "${standard_block_sha}" != "${strict_block_sha}" ]
    # Exactly one marker block (no duplication).
    [ "$(grep -c 'managed-by: selfdef login-defs-baseline' "${LEGACY_LOGIN_DEFS}")" = "1" ]
}

@test "INVARIANT: primary drop-in idempotent — byte-identical re-install does NOT rewrite (2026-06-06 idempotency fix)" {
    write_config "standard"
    run_wd
    [ -f "${DROPIN}" ]
    mtime_before="$(stat -c '%Y' "${DROPIN}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DROPIN}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: no render-timestamp in primary drop-in (defeats cmp -s)" {
    write_config "standard"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "${DROPIN}"
}

@test "INVARIANT: DRY_RUN does not write drop-in or modify legacy" {
    write_config "standard"
    sha_legacy_before="$(sha256sum "${LEGACY_LOGIN_DEFS}" | awk '{print $1}')"
    DRY_RUN=1 run_wd
    sha_legacy_after="$(sha256sum "${LEGACY_LOGIN_DEFS}" | awk '{print $1}')"
    ! [ -f "${DROPIN}" ]
    [ "${sha_legacy_before}" = "${sha_legacy_after}" ]
}

@test "drop-in is chmod 0644" {
    write_config "standard"
    run_wd
    [ "$(stat -c '%a' "${DROPIN}")" = "644" ]
}

@test "default profile is standard (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${DROPIN}" ]
}
