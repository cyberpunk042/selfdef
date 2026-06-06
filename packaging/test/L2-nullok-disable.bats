#!/usr/bin/env bats
# L2 functional suite for nullok-disable.
#
# nullok-disable closes the "empty-password-allowed" PAM
# configuration vector. When pam_unix.so (or pam_unix2.so) is
# configured with `nullok` (or `nullok_secure`), a user with an
# EMPTY password can log in — historically a debugging shortcut,
# but a routine pre-attack reconnaissance finding.
#
# Profiles:
#   audit   → walk /etc/pam.d/*; LOG findings; make NO changes
#   enforce → walk /etc/pam.d/*; back up affected files to
#             <file>.selfdef-nullok-backup AND sed-remove the
#             `nullok` (+ `nullok_secure`) tokens
#
# CRITICAL INVARIANTS:
#   - Backup-once: enforcing on a file that already has a
#     .selfdef-nullok-backup does NOT overwrite the existing
#     backup (preserve original distro state across re-applies).
#   - Symlink-skip: walking /etc/pam.d/* must skip symlinks
#     (common-* alias files on Debian; mutating the symlink
#     target risks scope-creep across PAM stacks).
#   - DRY_RUN preservation: dry-run must NOT write the backup,
#     must NOT mutate the source file.
#
# Run with: bats packaging/test/L2-nullok-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    CONF="${TMP}/nullok-disable.toml"
    PAM_D="${TMP}/pam.d"
    mkdir -p "${PAM_D}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_NULLOK_CONFIG="${CONF}" \
    SELFDEF_PAM_D="${PAM_D}" \
    bash "${WD}"
}

# Helper: write a PAM file that has a nullok-allowing pam_unix line.
write_vulnerable_pam() {
    local name="$1"
    cat > "${PAM_D}/${name}" <<EOF
# pam.d/${name}
auth sufficient pam_unix.so nullok try_first_pass
account required pam_unix.so
EOF
}

# Helper: write a PAM file with NO nullok (clean).
write_clean_pam() {
    local name="$1"
    cat > "${PAM_D}/${name}" <<EOF
# pam.d/${name}
auth required pam_unix.so try_first_pass
account required pam_unix.so
EOF
}

@test "missing config → die" {
    SELFDEF_NULLOK_CONFIG="${TMP}/missing.toml"
    run env SELFDEF_NULLOK_CONFIG="${SELFDEF_NULLOK_CONFIG}" \
        SELFDEF_PAM_D="${PAM_D}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env SELFDEF_NULLOK_CONFIG="${CONF}" \
        SELFDEF_PAM_D="${PAM_D}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be audit|enforce"* ]]
}

@test "missing PAM dir → die" {
    write_config "audit"
    run env SELFDEF_NULLOK_CONFIG="${CONF}" \
        SELFDEF_PAM_D="${TMP}/no-pam" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"PAM dir missing"* ]]
}

@test "audit profile LOGS nullok finding but does NOT mutate the file" {
    write_vulnerable_pam "login"
    pre_sha="$(sha256sum "${PAM_D}/login" | awk '{print $1}')"
    write_config "audit"
    run_wd 2>&1 | grep -q "FOUND nullok in"
    post_sha="$(sha256sum "${PAM_D}/login" | awk '{print $1}')"
    [ "${pre_sha}" = "${post_sha}" ]
    # No backup file should exist.
    ! [ -f "${PAM_D}/login.selfdef-nullok-backup" ]
}

@test "audit profile on clean PAM dir → no findings, no log entries" {
    write_clean_pam "login"
    write_config "audit"
    run_wd 2>&1 | grep -qv "FOUND nullok"
}

@test "enforce profile sed-removes nullok AND backs up original" {
    write_vulnerable_pam "login"
    pre_sha="$(sha256sum "${PAM_D}/login" | awk '{print $1}')"
    write_config "enforce"
    run_wd
    # Original is backed up byte-identical.
    [ -f "${PAM_D}/login.selfdef-nullok-backup" ]
    backup_sha="$(sha256sum "${PAM_D}/login.selfdef-nullok-backup" | awk '{print $1}')"
    [ "${pre_sha}" = "${backup_sha}" ]
    # Live file no longer has `nullok` (token-level removal).
    ! grep -qE '\bnullok\b' "${PAM_D}/login"
    # pam_unix.so is still present (only the dangerous token was
    # surgically removed).
    grep -q 'pam_unix\.so' "${PAM_D}/login"
}

@test "enforce profile also handles nullok_secure (alternate spelling)" {
    cat > "${PAM_D}/login" <<EOF
auth sufficient pam_unix.so nullok_secure try_first_pass
EOF
    write_config "enforce"
    run_wd
    ! grep -qE '\bnullok_secure\b' "${PAM_D}/login"
    ! grep -qE '\bnullok\b' "${PAM_D}/login"
}

@test "enforce profile leaves CLEAN PAM files alone (no backup created)" {
    write_clean_pam "login"
    pre_sha="$(sha256sum "${PAM_D}/login" | awk '{print $1}')"
    write_config "enforce"
    run_wd
    post_sha="$(sha256sum "${PAM_D}/login" | awk '{print $1}')"
    [ "${pre_sha}" = "${post_sha}" ]
    ! [ -f "${PAM_D}/login.selfdef-nullok-backup" ]
}

@test "INVARIANT: backup-once — re-applying enforce does NOT overwrite the existing backup" {
    write_vulnerable_pam "login"
    write_config "enforce"
    run_wd
    [ -f "${PAM_D}/login.selfdef-nullok-backup" ]
    backup_mtime_before="$(stat -c '%Y' "${PAM_D}/login.selfdef-nullok-backup")"
    # Re-apply (file no longer has nullok, so this is a no-op for
    # the modify step; backup should remain untouched).
    sleep 1
    run_wd
    backup_mtime_after="$(stat -c '%Y' "${PAM_D}/login.selfdef-nullok-backup")"
    [ "${backup_mtime_before}" = "${backup_mtime_after}" ]
}

@test "INVARIANT: symlink-skip — symlinks in /etc/pam.d are NOT walked (anti-scope-creep across PAM stacks)" {
    write_vulnerable_pam "common-auth"
    # Create a symlink (Debian's login → common-auth pattern).
    ln -s "${PAM_D}/common-auth" "${PAM_D}/login"
    write_config "enforce"
    run_wd
    # common-auth IS rewritten (a regular file).
    ! grep -qE '\bnullok\b' "${PAM_D}/common-auth"
    # The symlink itself stays a symlink (not mutated into a file).
    [ -L "${PAM_D}/login" ]
    # No spurious backup created for the symlink path itself.
    ! [ -f "${PAM_D}/login.selfdef-nullok-backup" ]
}

@test "INVARIANT: DRY_RUN does NOT write backup or mutate file" {
    write_vulnerable_pam "login"
    pre_sha="$(sha256sum "${PAM_D}/login" | awk '{print $1}')"
    write_config "enforce"
    DRY_RUN=1 run_wd
    post_sha="$(sha256sum "${PAM_D}/login" | awk '{print $1}')"
    [ "${pre_sha}" = "${post_sha}" ]
    ! [ -f "${PAM_D}/login.selfdef-nullok-backup" ]
}

@test "default profile is audit (no profile key — conservative read-only default)" {
    write_vulnerable_pam "login"
    pre_sha="$(sha256sum "${PAM_D}/login" | awk '{print $1}')"
    : > "${CONF}"
    run_wd 2>&1 | grep -q "FOUND nullok in"
    post_sha="$(sha256sum "${PAM_D}/login" | awk '{print $1}')"
    # default (audit) is non-mutating.
    [ "${pre_sha}" = "${post_sha}" ]
    ! [ -f "${PAM_D}/login.selfdef-nullok-backup" ]
}

@test "audited count + modified count surface in emit_status JSON" {
    write_vulnerable_pam "login"
    write_vulnerable_pam "su"
    write_clean_pam "passwd"
    write_config "enforce"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'audited=2'* ]]
    [[ "${output}" == *'modified=2'* ]]
}
