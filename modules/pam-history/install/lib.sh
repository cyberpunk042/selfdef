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

PWHISTORY_CONF="/etc/security/pwhistory.conf"
BACKUP_DIR="/var/lib/selfdef"
BACKUP_FILE="${BACKUP_DIR}/pam-history-distro-default.bak"
HEADER_MARKER="# managed-by: selfdef pam-history"

# Detect whether pam_pwhistory.so is wired into the PAM
# password stack. Same DETECT-AND-NOTICE pattern as
# pam-pwquality + pam-faillock.
detect_pam_wiring() {
    local wired_files=()
    for f in /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth; do
        if [[ -r "$f" ]] && grep -qE '^\s*password\s+\S+\s+pam_pwhistory\.so' "$f"; then
            wired_files+=("$f")
        fi
    done
    printf '%s\n' "${wired_files[@]}"
}
