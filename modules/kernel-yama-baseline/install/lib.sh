# Module-specific helpers for kernel-yama-baseline.
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

SYSCTL_DROPIN="/etc/sysctl.d/50-selfdef-yama.conf"
HEADER_MARKER="# managed-by: selfdef kernel-yama-baseline"

profile_to_value() {
    case "$1" in
        relaxed)  echo 1 ;;
        strict)   echo 2 ;;
        paranoid) echo 3 ;;
        *)        echo "?" ;;
    esac
}
