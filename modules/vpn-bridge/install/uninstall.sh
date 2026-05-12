#!/usr/bin/env bash
# vpn-bridge — uninstall.
#
# Stops + disables wg-quick@<iface>, removes our nftables forward
# table. Does NOT delete /etc/wireguard/<iface>.conf, the keys, or
# the wireguard-tools package — operator responsibility.

set -euo pipefail

MODULE="vpn-bridge"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_VPN_BRIDGE_CONFIG:-/etc/selfdef/modules/vpn-bridge.toml}"
NFT_RULESET_PATH="${SELFDEF_VPN_BRIDGE_NFT_PATH:-/etc/nftables.d/selfdef-vpn-bridge.conf}"

log() { echo "[vpn-bridge:uninstall] $*" >&2; }
emit_status() {
    local status="$1" message="$2"
    printf '{"module":"%s","status":"%s","message":"%s"}\n' \
        "$MODULE" "$status" "${message//\"/\\\"}"
}
run() {
    local desc="$1"; shift
    [[ "$1" == "--" ]] && shift
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY-RUN: $desc"
        log "    \$ $*"
    else
        log "$desc"
        "$@" || log "(continuing past failure)"
    fi
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

IFACE="wg0"
[[ -r "$CONFIG_FILE" ]] && IFACE=$(toml_get interface "$CONFIG_FILE" || echo "wg0")

service_name="wg-quick@${IFACE}.service"
if command -v systemctl >/dev/null; then
    if systemctl is-active --quiet "$service_name"; then
        run "stop $service_name" -- systemctl stop "$service_name"
    fi
    if systemctl is-enabled --quiet "$service_name" 2>/dev/null; then
        run "disable $service_name" -- systemctl disable "$service_name"
    fi
fi

if command -v nft >/dev/null && nft list table inet selfdef_vpn_bridge >/dev/null 2>&1; then
    run "delete nftables table inet selfdef_vpn_bridge" \
        -- nft delete table inet selfdef_vpn_bridge
fi
if [[ -f "$NFT_RULESET_PATH" ]]; then
    run "remove $NFT_RULESET_PATH" -- rm -f "$NFT_RULESET_PATH"
fi

emit_status "ok" "uninstalled (config + keys preserved)"
