#!/usr/bin/env bash
# vpn-bridge — check (dispatcher). No state changes.

set -euo pipefail

MODULE="vpn-bridge"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_VPN_BRIDGE_CONFIG:-/etc/selfdef/modules/vpn-bridge.toml}"
LIB_DIR="${SELFDEF_VPN_BRIDGE_LIB_DIR:-$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")}"
PROFILES_DIR="${SELFDEF_VPN_BRIDGE_PROFILES_DIR:-${LIB_DIR}/profiles}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || { emit_status "failed" "config not readable: $CONFIG_FILE"; exit 1; }

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "relay-via-server")

resolve_profile_script check
