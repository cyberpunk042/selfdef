# Module-specific helpers for dns-shield.
# Shared helpers (log, emit_status, die, run, toml_get) come from
# /usr/share/selfdef/lib/module-lib.sh.

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

# Sentinel markers that bracket selfdef-managed /etc/hosts content.
# Any external editor (operator's hand-edit, ansible, etc.) is free
# to touch lines OUTSIDE these markers; we touch nothing else.
DNS_SHIELD_BEGIN="# === selfdef dns-shield BEGIN (auto-generated; do not edit) ==="
DNS_SHIELD_END="# === selfdef dns-shield END ==="
