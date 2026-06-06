# Module-specific helpers for login-defs-baseline.
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

LOGIN_DEFS_D="${SELFDEF_LOGIN_DEFS_D:-/etc/login.defs.d}"
DROPIN="${LOGIN_DEFS_D}/50-selfdef-login-defs.conf"
# Fallback append target for distros without login.defs.d.
LEGACY_LOGIN_DEFS="${SELFDEF_LEGACY_LOGIN_DEFS:-/etc/login.defs}"
HEADER_MARKER="# managed-by: selfdef login-defs-baseline"
SENTINEL_KEYS=(PASS_MAX_DAYS PASS_MIN_DAYS PASS_WARN_AGE ENCRYPT_METHOD)
