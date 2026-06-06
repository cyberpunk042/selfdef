# Module-specific helpers for bluetooth-disable.
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

# Bluetooth service set. Different distros ship some
# combinations (bluez, bluez-obexd, bluealsa); we try all.
BT_UNITS=(
    "bluetooth.service"
    "bluetooth.target"
    "obex.service"
    "bluealsa.service"
)

# Bluetooth kernel modules to blacklist (mask profile).
BT_MODULES=(
    "btusb"
    "btintel"
    "btbcm"
    "btmtk"
    "btrtl"
    "bluetooth"
)

# SELFDEF_BT_MODPROBE_BLACKLIST added 2026-06-06 for L2 testability —
# live default unchanged.
MODPROBE_BLACKLIST="${SELFDEF_BT_MODPROBE_BLACKLIST:-/etc/modprobe.d/selfdef-bluetooth-blacklist.conf}"
HEADER_MARKER="# managed-by: selfdef bluetooth-disable"
