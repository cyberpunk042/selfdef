# Module-specific helpers for rare-network-protocols-disable.
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

MODPROBE_FILE="${SELFDEF_RAREPROTO_MODPROBE_FILE:-/etc/modprobe.d/selfdef-rare-network-protocols-blacklist.conf}"
HEADER_MARKER="# managed-by: selfdef rare-network-protocols-disable"

BASELINE_MODS=(dccp sctp rds tipc)
STRICT_MODS=(dccp sctp rds tipc atm can appletalk decnet ipx netrom ax25 rose x25)
