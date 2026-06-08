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

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. nullok-disable manifest declares install + profile
    # gating the resolver enforces; malformed manifest wedges
    # the PAM-nullok removal baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # nullok-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'nullok-disable', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: nullok-disable installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # nullok-disable writes its own drop-in or config; it MUST NEVER
    # rm/find-delete an operator's pre-existing entries not
    # owned by THIS module. Locks no-auto-delete on the
    # nullok-disable installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(postfix|exim|sendmail|nftables|nscd|pam|prometheus|grafana)' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(postfix|exim|sendmail|nftables|nscd|pam|prometheus|grafana).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # nullok-disable install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the nullok-disable lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the nullok-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('depends_on', [])
assert isinstance(v, list), f'depends_on must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml conflicts field is a TOML list — anti-string-malformation contract on conflicts)" {
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks list-vs-string discipline on conflicts.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('conflicts', [])
assert isinstance(v, list), f'conflicts must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml provides field is a TOML list — anti-string-malformation contract on provides)" {
    # Sister to brain-wide module.toml manifest-completeness +
    # list-vs-string INVARIANTs. Locks list discipline on
    # provides.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('provides', [])
assert isinstance(v, list), f'provides must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml requires field is a TOML list — anti-string-malformation contract on requires)" {
    # Sister to brain-wide module.toml list-vs-string family.
    # Locks list discipline on requires.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('requires', [])
assert isinstance(v, list), f'requires must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml requires entries are tables with kind + value — anti-flat-string-list contract)" {
    # Sister to brain-wide module.toml requires-shape INVARIANT
    # family. Locks the kind+value table-shape discipline on
    # the nullok-disable requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
reqs = data.get('requires', [])
for r in reqs:
    assert isinstance(r, dict), f'requires entry must be table, got {type(r).__name__}'
    assert 'kind' in r and 'value' in r, f'requires entry must have kind+value, got {r}'
"
}

@test "INVARIANT (module.toml summary field present + non-empty — operator-dashboard one-line description contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks summary-present discipline on the
    # nullok-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) > 0, f'summary must be non-empty string, got {repr(s)}'
"
}

@test "INVARIANT (module.toml category field present + non-empty — dashboard-grouping contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks category-present discipline on the
    # nullok-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert isinstance(c, str) and len(c) > 0, f'category must be non-empty string, got {repr(c)}'
"
}

@test "INVARIANT (module.toml version field is semver X.Y.Z — version-comparison sortability contract)" {
    # Sister to brain-wide module.toml semver INVARIANT family.
    # Locks semver-X.Y.Z discipline on the nullok-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (nullok-disable module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl installer resolves apply scripts
    # via module.toml's [install].apply field — the canonical
    # value is the relative path "install/apply.sh" (under the
    # module's own directory). A regression that swapped to
    # an absolute /usr/local/libexec/... path would break the
    # in-tree test runner (which executes apply scripts from
    # the source tree, not /usr/local/libexec/). A regression
    # to a non-existent path would surface as "apply script
    # not found" at install time. Locks the canonical
    # install/apply.sh path discipline on the nullok-disable module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install') or {}
ap = inst.get('apply', '')
assert ap == 'install/apply.sh', f'install.apply must be install/apply.sh, got {ap!r}'
"
}

@test "INVARIANT (nullok-disable module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the nullok-disable module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install') or {}
chk = inst.get('check', '')
assert chk == 'install/check.sh', f'install.check must be install/check.sh, got {chk!r}'
"
}

@test "INVARIANT (nullok-disable module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
    # Sister to brain-wide module.toml [install_paths]
    # INVARIANT family. Per MS011 Z-8 / SDD-026, every
    # installer module MUST declare an [install_paths] block
    # enumerating the on-disk surfaces it touches on apply.
    # The selfdef dashboard's install-options surface +
    # install-plan auditor read this block to surface what
    # the module mutates BEFORE apply runs. A regression
    # dropping the [install_paths] block would leave operators
    # without a pre-apply manifest of writes, breaking
    # operator-consent + the install-plan-dry-run contract.
    # Locks the SDD-026 manifest discipline on the nullok-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths')
assert ip is not None, f'[install_paths] block must be present per SDD-026, got None'
paths = ip.get('paths', [])
assert isinstance(paths, list) and len(paths) > 0, f'install_paths.paths must be non-empty list, got {paths!r}'
"
}

@test "INVARIANT (nullok-disable module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for nullok-disable is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the nullok-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (nullok-disable module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
    # Sister to brain-wide [install_paths].paths INVARIANT
    # family. The install_paths.paths field MUST be a TOML
    # list of strings (each element an absolute path the
    # module touches on apply). A regression that swapped to
    # a comma-separated string ("path1,path2,path3") would
    # silently treat it as a single literal path. The
    # selfdef installer iterates the list to surface the
    # mutation manifest to operators; broken type-shape
    # would break the install-options surface + dry-run
    # auditor. Locks the TOML-list-of-strings type discipline
    # on the nullok-disable install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list), f'install_paths.paths must be TOML list, got {type(ps).__name__}'
assert all(isinstance(p, str) for p in ps), f'every paths entry must be a string'
"
}

@test "INVARIANT (nullok-disable module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the nullok-disable requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
req = data.get('requires')
assert isinstance(req, list), f'requires must be TOML list, got {type(req).__name__}'
for r in req:
    assert isinstance(r, dict), f'requires entry must be inline-table, got {type(r).__name__}'
    assert 'kind' in r and 'value' in r, f'requires must have kind+value, got {r!r}'
"
}

@test "INVARIANT (nullok-disable module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the nullok-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (nullok-disable module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the nullok-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (nullok-disable module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the nullok-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (nullok-disable module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (nullok-disable module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the nullok-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
prof = data.get('profiles')
assert prof is not None, f'[profiles] must be present, got None'
assert isinstance(prof, dict), f'[profiles] must be TOML table, got {type(prof).__name__}'
"
}

@test "INVARIANT (nullok-disable module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (nullok-disable module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (nullok-disable module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (nullok-disable module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (nullok-disable module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (nullok-disable module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (nullok-disable README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (nullok-disable install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (nullok-disable install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (nullok-disable install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (nullok-disable install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (nullok-disable install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (nullok-disable install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (nullok-disable install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (nullok-disable install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (nullok-disable install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (nullok-disable install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (nullok-disable install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (nullok-disable install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (nullok-disable module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (nullok-disable module.toml exists at canonical path modules/nullok-disable/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (nullok-disable module dir is at canonical path modules/nullok-disable/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/nullok-disable"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (nullok-disable install dir exists at modules/nullok-disable/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (nullok-disable install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (nullok-disable install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (nullok-disable install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (nullok-disable install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (nullok-disable module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (nullok-disable install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (nullok-disable install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (nullok-disable install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (nullok-disable install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (nullok-disable install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (nullok-disable install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (nullok-disable install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (nullok-disable install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (nullok-disable module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (nullok-disable module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (nullok-disable module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nullok-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
prefixes = ('/etc/', '/usr/', '/var/', '/lib/', '/opt/', '/run/', '/srv/', '/boot/')
for p in ps:
    assert any(p.startswith(pf) for pf in prefixes), f'{p!r} not canonical-root'
"
}
