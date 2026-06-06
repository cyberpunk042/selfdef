# Module-specific helpers for selinux-baseline.
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

# SELFDEF_SELINUX_CONFIG_FILE + SELFDEF_AUTORELABEL_FILE added
# 2026-06-06 for L2 testability — live defaults unchanged.
SELINUX_CONFIG="${SELFDEF_SELINUX_CONFIG_FILE:-/etc/selinux/config}"
SELFDEF_AUTORELABEL_FILE="${SELFDEF_AUTORELABEL_FILE:-/.autorelabel}"

# Returns the current live mode: Enforcing / Permissive / Disabled
# / unavailable.
selinux_live_mode() {
    if command -v getenforce >/dev/null 2>&1; then
        getenforce 2>/dev/null || echo "unavailable"
    else
        echo "unavailable"
    fi
}

# Returns the persisted SELINUX= value from /etc/selinux/config.
selinux_config_mode() {
    [[ -r "$SELINUX_CONFIG" ]] || { echo "absent"; return; }
    awk -F= '/^SELINUX=/{print $2; exit}' "$SELINUX_CONFIG" 2>/dev/null || echo "absent"
}

# Count recent AVC denials (best-effort; ausearch or journal).
selinux_recent_denials() {
    if command -v ausearch >/dev/null 2>&1; then
        ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | grep -c 'denied' || echo 0
    elif command -v journalctl >/dev/null 2>&1; then
        journalctl -k --since "1 hour ago" 2>/dev/null | grep -c 'avc:.*denied' || echo 0
    else
        echo 0
    fi
}
