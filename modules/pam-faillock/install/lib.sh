# Module-specific helpers for pam-faillock.
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

FAILLOCK_CONF="${SELFDEF_FAILLOCK_CONF:-/etc/security/faillock.conf}"
FAILLOCK_BACKUP="${FAILLOCK_CONF}.selfdef-backup"
FAILLOCK_DIR="${SELFDEF_FAILLOCK_DIR:-/var/lib/faillock}"
FAILLOCK_MARKER="# === selfdef pam-faillock-managed (do not hand-edit) ==="
