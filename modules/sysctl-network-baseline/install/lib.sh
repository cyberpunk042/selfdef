# Module-specific helpers for sysctl-network-baseline.
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

SYSCTL_DROPIN="/etc/sysctl.d/50-selfdef-network-baseline.conf"
HEADER_MARKER="# managed-by: selfdef sysctl-network-baseline"

# Sentinel keys for drift detection (representative subset; check.sh
# verifies their live runtime values match expectation per profile).
SENTINEL_KEYS_BASELINE=(
    "net.ipv4.conf.all.accept_redirects:0"
    "net.ipv4.conf.all.accept_source_route:0"
    "net.ipv4.conf.all.rp_filter:1"
    "net.ipv4.tcp_syncookies:1"
    "net.ipv4.conf.all.log_martians:1"
    "net.ipv6.conf.all.accept_redirects:0"
)
SENTINEL_KEYS_ROUTER=(
    "net.ipv4.conf.all.accept_redirects:0"
    "net.ipv4.ip_forward:1"
    "net.ipv6.conf.all.forwarding:1"
    "net.ipv4.tcp_syncookies:1"
)
SENTINEL_KEYS_PARANOID=(
    "net.ipv4.conf.all.accept_redirects:0"
    "net.ipv4.icmp_echo_ignore_all:1"
    "net.ipv6.conf.all.disable_ipv6:1"
)
