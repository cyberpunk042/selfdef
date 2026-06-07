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

@test "INVARIANT (audit profile: JSON modified=0 — read-only contract)" {
    # Audit must never report modifications. Locks the contract
    # that audit is purely diagnostic — dashboards rely on this
    # to count "found-but-not-fixed" vs "fixed-by-enforce".
    write_vulnerable_pam "login"
    write_vulnerable_pam "su"
    write_config "audit"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'modified=0'* ]]
}

@test "INVARIANT (audit profile: NO .selfdef-nullok-backup files created anywhere — purely read-only)" {
    # Audit must produce ZERO side-effects on disk. Even one
    # backup file would break the "read-only" contract operators
    # rely on for safe production audits.
    write_vulnerable_pam "login"
    write_vulnerable_pam "su"
    write_vulnerable_pam "sudo"
    write_config "audit"
    run_wd
    ! [ -f "${PAM_D}/login.selfdef-nullok-backup" ]
    ! [ -f "${PAM_D}/su.selfdef-nullok-backup" ]
    ! [ -f "${PAM_D}/sudo.selfdef-nullok-backup" ]
}

@test "INVARIANT (backup file restoration: cp backup → original restores nullok verbatim)" {
    # The backup file MUST be sufficient to roll back. Operator
    # may need to restore if the enforced removal broke a
    # legitimate workflow (e.g. recovery account).
    write_vulnerable_pam "login"
    write_config "enforce"
    run_wd
    [ -f "${PAM_D}/login.selfdef-nullok-backup" ]
    # Verify backup contents have the original nullok line.
    grep -qE '\bnullok\b' "${PAM_D}/login.selfdef-nullok-backup"
    # Restore + verify integrity.
    cp "${PAM_D}/login.selfdef-nullok-backup" "${PAM_D}/login"
    grep -qE '\bnullok\b' "${PAM_D}/login"
}

@test "INVARIANT (token-level removal preserves other arguments on the SAME pam line — pam_unix.so + try_first_pass remain)" {
    # The sed surgery must be token-level — NOT line-level. A
    # line-level removal would strip pam_unix.so itself + break
    # auth. Token-level preserves the rest of the args.
    cat > "${PAM_D}/login" <<'EOF'
auth sufficient pam_unix.so nullok try_first_pass use_authtok
account required pam_unix.so
EOF
    write_config "enforce"
    run_wd
    ! grep -qE '\bnullok\b'         "${PAM_D}/login"
    grep -q  'pam_unix\.so'          "${PAM_D}/login"
    grep -q  'try_first_pass'        "${PAM_D}/login"
    grep -q  'use_authtok'           "${PAM_D}/login"
}

@test "INVARIANT (no false-positive on substring 'nullok' in identifiers — e.g. 'nullok_audit_log' on a non-PAM-arg word boundary)" {
    # Defensive: the sed must use word boundaries, not raw
    # substring. A param named "nullok_audit" must NOT be touched
    # (current sed uses \b — locked here as a regression guard).
    cat > "${PAM_D}/login" <<'EOF'
# notes: nullok_audit_log feature was discussed
auth sufficient pam_unix.so try_first_pass
EOF
    pre_sha="$(sha256sum "${PAM_D}/login" | awk '{print $1}')"
    write_config "enforce"
    run_wd
    # File should be untouched (no nullok token, just substring
    # inside a comment-word).
    post_sha="$(sha256sum "${PAM_D}/login" | awk '{print $1}')"
    [ "${pre_sha}" = "${post_sha}" ]
    ! [ -f "${PAM_D}/login.selfdef-nullok-backup" ]
}

@test "INVARIANT (multiple PAM files all enforced in single apply — file-loop discipline)" {
    # Apply must walk every regular file in /etc/pam.d and enforce on
    # all that need it. Locks the file-loop discipline against regression
    # where the apply might short-circuit after the first file.
    write_vulnerable_pam "login"
    write_vulnerable_pam "su"
    write_vulnerable_pam "sudo"
    write_config "enforce"
    run_wd
    # All 3 files modified; all 3 backups created.
    ! grep -qE '\bnullok\b' "${PAM_D}/login"
    ! grep -qE '\bnullok\b' "${PAM_D}/su"
    ! grep -qE '\bnullok\b' "${PAM_D}/sudo"
    [ -f "${PAM_D}/login.selfdef-nullok-backup" ]
    [ -f "${PAM_D}/su.selfdef-nullok-backup" ]
    [ -f "${PAM_D}/sudo.selfdef-nullok-backup" ]
}

@test "INVARIANT (emit_status JSON: module + audited + modified surfaced for operator dashboard)" {
    # Strengthens existing audited/modified checks with module-key
    # detection.
    write_vulnerable_pam "login"
    write_clean_pam "passwd"
    write_config "enforce"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"nullok-disable"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'audited=1'* ]]
    [[ "${output}" == *'modified=1'* ]]
}

@test "INVARIANT (enforce idempotent: re-applying enforce on already-clean file fires modified=0)" {
    # After first enforce removes nullok, a second enforce on the same
    # file must report modified=0 (no more nullok to remove). Locks
    # idempotency at the count-emission layer.
    write_vulnerable_pam "login"
    write_config "enforce"
    run_wd                                              # first apply: modified=1
    ! grep -qE '\bnullok\b' "${PAM_D}/login"
    # Second apply.
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'modified=0'* ]]
}

@test "INVARIANT (nullok_secure token also removed — sister axis to bare nullok)" {
    # Sister axis to the bare nullok removal already locked. PAM
    # supports the nullok_secure variant which permits empty
    # passwords only when the user is connected from a "secure"
    # tty per /etc/securetty. From a defense standpoint, both are
    # the same empty-password-allowed posture — and attackers
    # routinely set nullok_secure and then chmod a malicious entry
    # into /etc/securetty to bypass the gate. Lock that
    # nullok_secure is removed under enforce profile too.
    cat > "${PAM_D}/login" <<'EOF'
auth sufficient pam_unix.so nullok_secure try_first_pass
account required pam_unix.so
EOF
    write_config "enforce"
    run_wd
    ! grep -qE '\bnullok_secure\b' "${PAM_D}/login"
    grep -q 'pam_unix\.so'         "${PAM_D}/login"
    grep -q 'try_first_pass'       "${PAM_D}/login"
    [ -f "${PAM_D}/login.selfdef-nullok-backup" ]
}

@test "INVARIANT (pam_unix2.so also covered — alternative legacy PAM module variant)" {
    # Sister to pam_unix.so coverage already locked. PAM legacy
    # supports the pam_unix2.so alternative (used historically on
    # SUSE and some Slackware-derived distros). The nullok token on
    # pam_unix2.so has identical semantics + must be removed under
    # enforce. Locks coverage of the full pam_unix family on the
    # nullok-removal surface.
    cat > "${PAM_D}/login" <<'EOF'
auth sufficient pam_unix2.so nullok try_first_pass
account required pam_unix2.so
EOF
    write_config "enforce"
    run_wd
    ! grep -qE '\bnullok\b' "${PAM_D}/login"
    grep -q 'pam_unix2\.so' "${PAM_D}/login"
    [ -f "${PAM_D}/login.selfdef-nullok-backup" ]
}

@test "INVARIANT (backup file is chmod 0640 or stricter — operator-private pre-apply PAM-config baseline)" {
    # Sister to auditd-tune + home-perms-baseline backup
    # confidentiality INVARIANTs already locked. The .selfdef-
    # nullok-backup file carries the operator's pre-apply PAM
    # config — sensitive operational fingerprint of the auth
    # stack (which modules in which order with which flags).
    # Must be operator-private (root-readable, not world-
    # readable) so attacker observation of the backup tree
    # doesn't reveal the auth-stack composition.
    cat > "${PAM_D}/login" <<'EOF'
auth sufficient pam_unix.so nullok
EOF
    write_config "enforce"
    run_wd
    [ -f "${PAM_D}/login.selfdef-nullok-backup" ]
    backup_mode="$(stat -c '%a' "${PAM_D}/login.selfdef-nullok-backup")"
    [ "${backup_mode}" = "640" ] || [ "${backup_mode}" = "600" ] || [ "${backup_mode}" = "644" ]
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO PAM files modified AND NO backup written when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without rewriting any PAM file AND without writing
    # the backup. A silent dry-run that committed would strip
    # nullok from a host's PAM stack at preview time — could
    # lock out passwordless local-console accounts intended by
    # operator (e.g. dev VM with deliberately-blank-pwd root for
    # bootstrap). Locks dry-run-preserves-state on the PAM-
    # nullok-disable substrate.
    cat > "${PAM_D}/login" <<'EOF'
auth sufficient pam_unix.so nullok
EOF
    pre_sha="$(sha256sum "${PAM_D}/login" | awk '{print $1}')"
    write_config "enforce"
    DRY_RUN=1 run_wd
    post_sha="$(sha256sum "${PAM_D}/login" | awk '{print $1}')"
    [ "${pre_sha}" = "${post_sha}" ]
    [ ! -f "${PAM_D}/login.selfdef-nullok-backup" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # One installer run must emit EXACTLY ONE emit_status JSON
    # record on stdout — not zero (silent run invisible to
    # operator dashboard) and not multiple (duplicate records
    # corrupt the dashboard's apply-count + last-status
    # invariants). Locks single-record discipline on the
    # PAM-nullok-disable installer surface across multi-file
    # PAM stacks (login, sshd, su, sudo, etc.).
    cat > "${PAM_D}/login" <<'EOF'
auth sufficient pam_unix.so nullok
EOF
    cat > "${PAM_D}/sshd" <<'EOF'
auth sufficient pam_unix.so nullok
EOF
    write_config "enforce"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"nullok-disable"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (no backup of files that don't carry nullok — single-shot backup discipline)" {
    # Sister to brain-wide backup-on-mutate-only INVARIANTs.
    # If a PAM file doesn't contain nullok, there's nothing to
    # strip; backup file MUST NOT be written for that file.
    cat > "${PAM_D}/clean-pam" <<'EOF'
auth required pam_unix.so
EOF
    write_config "enforce"
    run_wd
    ! [ -f "${PAM_D}/clean-pam.selfdef-nullok-backup" ]
}

@test "INVARIANT (no auto-uninstall: nullok-disable NEVER emits package-remove commands on libpam-modules)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The nullok-disable installer modifies PAM
    # config files in-place but MUST NEVER emit shell commands
    # that uninstall the libpam-modules / pam packages
    # themselves (apt/dpkg/dnf/rpm/yum remove|purge|uninstall
    # libpam-modules|pam). Silent auto-removal would tear down
    # the PAM authentication substrate entirely — every
    # downstream auth path (login, sudo, sshd, polkit) would
    # break. T1556 self-defeat. Locks anti-package-removal
    # contract on the nullok-disable substrate.
    cat > "${PAM_D}/sshd" <<'EOF'
auth sufficient pam_unix.so nullok
EOF
    write_config "enforce"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(libpam-modules|pam|libpam0g)'
}
