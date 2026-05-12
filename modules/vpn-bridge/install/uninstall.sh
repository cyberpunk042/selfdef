#!/usr/bin/env bash
# vpn-bridge — uninstall (dispatcher).

set -euo pipefail

MODULE="vpn-bridge"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_VPN_BRIDGE_CONFIG:-/etc/selfdef/modules/vpn-bridge.toml}"
LIB_DIR="${SELFDEF_VPN_BRIDGE_LIB_DIR:-$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")}"
PROFILES_DIR="${SELFDEF_VPN_BRIDGE_PROFILES_DIR:-${LIB_DIR}/profiles}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

# Uninstall is best-effort: if the config went missing we still try
# to clean up by guessing relay-via-server (the default profile).
PROFILE="relay-via-server"
if [[ -r "$CONFIG_FILE" ]]; then
    PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "relay-via-server")
fi

resolve_profile_script uninstall
