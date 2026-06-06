# Module-specific helpers for pam-history.
# shellcheck disable=SC1090,SC2034
SELFDEF_MODULE_LIB_VERSION_REQUIRED=2

if [[ -n "${SELFDEF_MODULE_LIB:-}" && -r "${SELFDEF_MODULE_LIB}" ]]; then
    # shellcheck disable=SC1090
    source "${SELFDEF_MODULE_LIB}"
elif [[ -r "${LIB_DIR}/../../../packaging/lib/module-lib.sh" ]]; then
    # shellcheck disable=SC1091
    source "${LIB_DIR}/../../../packaging/lib/module-lib.sh"
elif [[ -r "/usr/share/selfdef/lib/module-lib.sh" ]]; then
    # shellcheck disable=SC1091
    source "/usr/share/selfdef/lib/module-lib.sh"
else
    echo "ERROR: cannot locate module-lib.sh (set SELFDEF_MODULE_LIB)" >&2
    exit 2
fi

# SELFDEF_PWHISTORY_CONF + SELFDEF_PWHISTORY_BACKUP_DIR added
# 2026-06-06 for L2 testability — live defaults unchanged.
PWHISTORY_CONF="${SELFDEF_PWHISTORY_CONF:-/etc/security/pwhistory.conf}"
BACKUP_DIR="${SELFDEF_PWHISTORY_BACKUP_DIR:-/var/lib/selfdef}"
BACKUP_FILE="${BACKUP_DIR}/pam-history-distro-default.bak"
HEADER_MARKER="# managed-by: selfdef pam-history"

# SELFDEF_PWHISTORY_PAM_DIR added 2026-06-06 for L2 testability —
# detect_pam_wiring()'s scan-root is overridable so tests can
# point at a tmp /etc/pam.d-like directory.
detect_pam_wiring() {
    local pam_dir="${SELFDEF_PWHISTORY_PAM_DIR:-/etc/pam.d}"
    local wired_files=()
    for f in "${pam_dir}/common-password" "${pam_dir}/system-auth" "${pam_dir}/password-auth"; do
        if [[ -r "$f" ]] && grep -qE '^\s*password\s+\S+\s+pam_pwhistory\.so' "$f"; then
            wired_files+=("$f")
        fi
    done
    printf '%s\n' "${wired_files[@]}"
}
