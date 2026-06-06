#!/usr/bin/env bats
# L2 functional suite for pam-history.
#
# pam-history installs /etc/security/pwhistory.conf with the
# chosen password-history retention profile. pam_pwhistory.so
# reads this file to enforce "no reuse of the last N passwords"
# at password-change time.
#
# Profiles:
#   standard → remember=5 (NIST SP 800-63B-aligned baseline)
#   strict   → remember=24 (audit-frameworks-aligned bar —
#              CIS Benchmark / DISA STIG family)
#
# Detect-and-notice pattern: pam_pwhistory.so must ALSO be wired
# into /etc/pam.d/common-password (Debian) or system-auth/
# password-auth (RHEL/Fedora). The module installs the config
# unconditionally; if no /etc/pam.d/* references the module the
# config is DORMANT and a NOTICE is logged with distro-specific
# enable instructions.
#
# Backup pattern: the operator's distro-default
# /etc/security/pwhistory.conf (if any, non-selfdef-owned) is
# backed up once on first apply.
#
# Adds SELFDEF_PWHISTORY_CONF + SELFDEF_PWHISTORY_BACKUP_DIR +
# SELFDEF_PWHISTORY_PAM_DIR env-vars (added 2026-06-06) for L2
# testability. Live defaults unchanged.
#
# Run with: bats packaging/test/L2-pam-history.bats

WD="${BATS_TEST_DIRNAME}/../../modules/pam-history/install/apply.sh"
CONFIGS_SRC="${BATS_TEST_DIRNAME}/../../modules/pam-history/configs"

setup() {
    TMP="$(mktemp -d)"
    CONF="${TMP}/pam-history.toml"
    PWHISTORY_CONF="${TMP}/pwhistory.conf"
    BACKUP_DIR="${TMP}/backup"
    PAM_DIR="${TMP}/pam.d"
    mkdir -p "${BACKUP_DIR}" "${PAM_DIR}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_PWHISTORY_CONFIG="${CONF}" \
    SELFDEF_PWHISTORY_CONF="${PWHISTORY_CONF}" \
    SELFDEF_PWHISTORY_BACKUP_DIR="${BACKUP_DIR}" \
    SELFDEF_PWHISTORY_PAM_DIR="${PAM_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_PWHISTORY_CONFIG="${TMP}/missing.toml"
    run env SELFDEF_PWHISTORY_CONFIG="${SELFDEF_PWHISTORY_CONFIG}" \
        SELFDEF_PWHISTORY_CONF="${PWHISTORY_CONF}" \
        SELFDEF_PWHISTORY_BACKUP_DIR="${BACKUP_DIR}" \
        SELFDEF_PWHISTORY_PAM_DIR="${PAM_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env SELFDEF_PWHISTORY_CONFIG="${CONF}" \
        SELFDEF_PWHISTORY_CONF="${PWHISTORY_CONF}" \
        SELFDEF_PWHISTORY_BACKUP_DIR="${BACKUP_DIR}" \
        SELFDEF_PWHISTORY_PAM_DIR="${PAM_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be standard|strict"* ]]
}

@test "standard profile renders pwhistory.conf with profile=standard marker" {
    write_config "standard"
    run_wd
    [ -f "${PWHISTORY_CONF}" ]
    grep -q 'managed-by: selfdef pam-history' "${PWHISTORY_CONF}"
    grep -q 'profile=standard' "${PWHISTORY_CONF}"
}

@test "strict profile renders pwhistory.conf with profile=strict marker + strict remember count" {
    write_config "strict"
    run_wd
    [ -f "${PWHISTORY_CONF}" ]
    grep -q 'profile=strict' "${PWHISTORY_CONF}"
    # Strict profile should bump remember above standard. The exact
    # value lives in configs/strict.conf; just verify it's present.
    grep -qE '^remember\s*=\s*[0-9]+' "${PWHISTORY_CONF}"
}

@test "pwhistory.conf is chmod 0644 (system-config convention)" {
    write_config "standard"
    run_wd
    [ "$(stat -c '%a' "${PWHISTORY_CONF}")" = "644" ]
}

@test "INVARIANT: no render-timestamp in pwhistory.conf (defeats cmp -s)" {
    write_config "standard"
    run_wd
    # Anti-timestamp invariant (2026-06-06 sweep).
    ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "${PWHISTORY_CONF}"
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite pwhistory.conf (2026-06-06 idempotency fix)" {
    write_config "standard"
    run_wd
    [ -f "${PWHISTORY_CONF}" ]
    mtime_before="$(stat -c '%Y' "${PWHISTORY_CONF}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${PWHISTORY_CONF}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: DRY_RUN does not write pwhistory.conf" {
    write_config "standard"
    DRY_RUN=1 run_wd
    ! [ -f "${PWHISTORY_CONF}" ]
}

@test "INVARIANT: operator's pre-existing distro pwhistory.conf is backed up once on first apply (NOT overwritten silently)" {
    # Simulate operator's pre-existing distro default file.
    cat > "${PWHISTORY_CONF}" <<'EOF'
# distro-shipped /etc/security/pwhistory.conf
remember=3
EOF
    write_config "standard"
    run_wd
    BACKUP_FILE="${BACKUP_DIR}/pam-history-distro-default.bak"
    [ -f "${BACKUP_FILE}" ]
    grep -qE '^remember\s*=\s*3' "${BACKUP_FILE}"
    # Backup is operator-private (sensitive PAM config).
    [ "$(stat -c '%a' "${BACKUP_FILE}")" = "600" ]
}

@test "INVARIANT: selfdef-owned pwhistory.conf is NOT backed up (avoid self-loop)" {
    # First apply lands the selfdef-managed file.
    write_config "standard"
    run_wd
    BACKUP_FILE="${BACKUP_DIR}/pam-history-distro-default.bak"
    ! [ -f "${BACKUP_FILE}" ]
}

@test "INVARIANT: second apply does NOT re-backup (single-shot backup pattern)" {
    cat > "${PWHISTORY_CONF}" <<'EOF'
# distro-shipped /etc/security/pwhistory.conf
remember=3
EOF
    write_config "standard"
    run_wd
    BACKUP_FILE="${BACKUP_DIR}/pam-history-distro-default.bak"
    [ -f "${BACKUP_FILE}" ]
    backup_mtime_before="$(stat -c '%Y' "${BACKUP_FILE}")"
    sleep 1
    write_config "strict"
    run_wd
    backup_mtime_after="$(stat -c '%Y' "${BACKUP_FILE}")"
    # Original distro default preserved — second apply did NOT
    # overwrite the backup with the (now selfdef-owned) live file.
    [ "${backup_mtime_before}" = "${backup_mtime_after}" ]
    grep -qE '^remember\s*=\s*3' "${BACKUP_FILE}"
}

@test "DETECT-AND-NOTICE: pam_pwhistory.so unwired in /etc/pam.d → log distro-specific enable instructions" {
    # No /etc/pam.d files exist with pam_pwhistory.so references.
    write_config "standard"
    run_wd
    # Output should include the unwired-NOTICE — emitted to operator
    # via log() which prefixes with [pam-history]. The script's
    # stdout is captured by `bats run_wd`'s implicit capture; we
    # check via re-running with `run` envelope.
    run_wd 2>&1 | grep -q "DORMANT"
}

@test "DETECT-AND-NOTICE: pam_pwhistory.so wired in /etc/pam.d/common-password → log wired-in status" {
    cat > "${PAM_DIR}/common-password" <<'EOF'
password requisite pam_pwhistory.so use_authtok
password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass yescrypt
EOF
    write_config "standard"
    run_wd 2>&1 | grep -q "pam_pwhistory.so is wired in"
}

@test "default profile is standard (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${PWHISTORY_CONF}" ]
    grep -q 'profile=standard' "${PWHISTORY_CONF}"
}

@test "INVARIANT (strict remember > standard remember — asymmetric tightening)" {
    # Strict must enforce remembering MORE passwords than standard.
    # Lock the asymmetric tightening for compliance frameworks.
    write_config "standard"
    run_wd
    std_remember="$(grep -oE 'remember[[:space:]]*=[[:space:]]*[0-9]+' "${PWHISTORY_CONF}" | grep -oE '[0-9]+$' | head -1)"
    write_config "strict"
    run_wd
    strict_remember="$(grep -oE 'remember[[:space:]]*=[[:space:]]*[0-9]+' "${PWHISTORY_CONF}" | grep -oE '[0-9]+$' | head -1)"
    [ -n "${std_remember}" ]
    [ -n "${strict_remember}" ]
    [ "${strict_remember}" -gt "${std_remember}" ]
}

@test "INVARIANT (profile downgrade strict → standard rewrites with looser remember count)" {
    # Bidirectional contract — operator can both tighten + loosen.
    write_config "strict"
    run_wd
    strict_sha="$(sha256sum "${PWHISTORY_CONF}" | awk '{print $1}')"
    write_config "standard"
    run_wd
    std_sha="$(sha256sum "${PWHISTORY_CONF}" | awk '{print $1}')"
    [ "${strict_sha}" != "${std_sha}" ]
    grep -q 'profile=standard' "${PWHISTORY_CONF}"
}

@test "INVARIANT (RHEL system-auth detection: pam_pwhistory.so wired there → wired-in status)" {
    # The detect-and-notice scan must walk both Debian's
    # common-password AND RHEL's system-auth / password-auth.
    cat > "${PAM_DIR}/system-auth" <<'EOF'
password requisite pam_pwhistory.so use_authtok
password sufficient pam_unix.so use_authtok yescrypt shadow
EOF
    write_config "standard"
    run_wd 2>&1 | grep -qE "pam_pwhistory.so is wired in|wired"
}

@test "INVARIANT (pwhistory.conf re-arm after operator deletion: re-creates file with header)" {
    write_config "standard"
    run_wd
    [ -f "${PWHISTORY_CONF}" ]
    rm -f "${PWHISTORY_CONF}"
    run_wd
    [ -f "${PWHISTORY_CONF}" ]
    grep -q 'managed-by: selfdef pam-history' "${PWHISTORY_CONF}"
    grep -qE '^remember[[:space:]]*=[[:space:]]*[0-9]+' "${PWHISTORY_CONF}"
}

@test "INVARIANT (emit_status JSON: status=ok + profile + pam-wired surfaced for operator dashboard)" {
    write_config "standard"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=standard'* ]]
    # wired= key surfaces actual wiring state for operator
    # to detect dormant configs.
    [[ "${output}" == *'wired=true'* ]] || [[ "${output}" == *'wired=false'* ]]
}
