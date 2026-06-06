# Module-specific helpers for firewalld-baseline.
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

# SELFDEF_FIREWALLD_BACKUP_DIR + SELFDEF_FIREWALLD_BACKUP_FILE +
# SELFDEF_FIREWALLD_ZONE added 2026-06-06 for L2 testability —
# live defaults unchanged.
BACKUP_DIR="${SELFDEF_FIREWALLD_BACKUP_DIR:-/var/lib/selfdef}"
BACKUP_FILE="${SELFDEF_FIREWALLD_BACKUP_FILE:-${BACKUP_DIR}/firewalld-default-zone.bak}"

# The selfdef-managed zone we configure + set as default.
SELFDEF_ZONE="${SELFDEF_FIREWALLD_ZONE:-selfdef}"
