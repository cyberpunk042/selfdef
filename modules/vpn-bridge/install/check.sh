#!/usr/bin/env bash
# vpn-bridge — check. No state changes. JSON status line on stdout.

set -euo pipefail

MODULE="vpn-bridge"
CONFIG_FILE="${SELFDEF_VPN_BRIDGE_CONFIG:-/etc/selfdef/modules/vpn-bridge.toml}"
WG_CONF_DIR="${SELFDEF_VPN_BRIDGE_WG_DIR:-/etc/wireguard}"

emit_status() {
    local status="$1" message="$2"
    printf '{"module":"%s","status":"%s","message":"%s"}\n' \
        "$MODULE" "$status" "${message//\"/\\\"}"
}
toml_get() {
    local key="$1" file="$2"
    local line
    line=$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$file" | head -1 || true)
    [[ -z "$line" ]] && return 1
    line="${line#*=}"; line="${line## }"; line="${line%% #*}"
    line="${line%\"}"; line="${line#\"}"
    printf '%s' "$line"
}

problems=()

[[ -r "$CONFIG_FILE" ]] || { emit_status "failed" "config not readable: $CONFIG_FILE"; exit 1; }

IFACE=$(toml_get interface "$CONFIG_FILE" || echo "wg0")
FORWARD_TO_LAN=$(toml_get forward_to_lan "$CONFIG_FILE" || echo "")

if [[ ! -r "${WG_CONF_DIR}/${IFACE}.conf" ]]; then
    problems+=("wg-quick config missing: ${WG_CONF_DIR}/${IFACE}.conf")
fi

if command -v systemctl >/dev/null; then
    if ! systemctl is-active --quiet "wg-quick@${IFACE}.service"; then
        problems+=("wg-quick@${IFACE}.service not active")
    fi
fi

# Interface exists and is up.
if command -v ip >/dev/null; then
    if ! ip -o link show "$IFACE" >/dev/null 2>&1; then
        problems+=("wireguard interface $IFACE not present")
    fi
fi

# Forward rules loaded if requested.
if [[ -n "$FORWARD_TO_LAN" ]] && command -v nft >/dev/null; then
    if ! nft list table inet selfdef_vpn_bridge >/dev/null 2>&1; then
        problems+=("nftables forward table inet selfdef_vpn_bridge not loaded")
    fi
fi

if [[ "${#problems[@]}" -eq 0 ]]; then
    emit_status "ok" "wg-quick@${IFACE} active; ${FORWARD_TO_LAN:+forward → $FORWARD_TO_LAN; }overlay live"
    exit 0
else
    msg=$(IFS=';'; printf '%s' "${problems[*]}")
    emit_status "failed" "$msg"
    exit 1
fi
