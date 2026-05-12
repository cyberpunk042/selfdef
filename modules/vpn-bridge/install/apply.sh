#!/usr/bin/env bash
# vpn-bridge — apply.
#
# Manages: wg-quick@<iface> service state, optional nftables FORWARD
# rules for the wg interface. Does NOT render /etc/wireguard/<iface>.conf
# — operator owns that. See README for the wg-quick config templates.
#
# Idempotent. SELFDEF_DRY_RUN=1 aware. Emits a JSON status line.

set -euo pipefail

MODULE="vpn-bridge"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_VPN_BRIDGE_CONFIG:-/etc/selfdef/modules/vpn-bridge.toml}"
TEMPLATE_DIR="${SELFDEF_VPN_BRIDGE_TEMPLATES:-/usr/share/selfdef/modules/vpn-bridge/templates}"
NFT_RULESET_PATH="${SELFDEF_VPN_BRIDGE_NFT_PATH:-/etc/nftables.d/selfdef-vpn-bridge.conf}"
WG_CONF_DIR="${SELFDEF_VPN_BRIDGE_WG_DIR:-/etc/wireguard}"

# ---------------------------------------------------------------- helpers
log() { echo "[vpn-bridge] $*" >&2; }
emit_status() {
    local status="$1" message="$2"
    printf '{"module":"%s","status":"%s","message":"%s"}\n' \
        "$MODULE" "$status" "${message//\"/\\\"}"
}
die() { emit_status "failed" "$*"; exit 1; }
run() {
    local desc="$1"; shift
    [[ "$1" == "--" ]] && shift
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY-RUN: $desc"
        log "    \$ $*"
    else
        log "$desc"
        "$@"
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

# ---------------------------------------------------------------- preflight
[[ -r "$CONFIG_FILE" ]] || die "config file not readable: $CONFIG_FILE"
command -v wg        >/dev/null || die "wg(8) missing"
command -v wg-quick  >/dev/null || die "wg-quick(8) missing"
command -v ip        >/dev/null || die "ip(8) missing"
command -v nft       >/dev/null || die "nft(8) missing"
command -v systemctl >/dev/null || die "systemctl missing"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "relay-via-server")
ROLE=$(toml_get role "$CONFIG_FILE" || echo "endpoint")
IFACE=$(toml_get interface "$CONFIG_FILE" || echo "wg0")
FORWARD_TO_LAN=$(toml_get forward_to_lan "$CONFIG_FILE" || echo "")

case "$PROFILE" in
    relay-via-server) ;;
    *) die "profile must be relay-via-server (only profile in v0.1.0), got '$PROFILE'" ;;
esac
case "$ROLE" in
    endpoint|relay) ;;
    *) die "role must be endpoint|relay, got '$ROLE'" ;;
esac
[[ "$IFACE" =~ ^[a-zA-Z0-9_-]+$ ]] || die "interface name has unsafe characters: '$IFACE'"

# The operator-owned wg-quick config must exist before we can start
# the service. Fail closed with a clear message if it doesn't.
WG_CONF="${WG_CONF_DIR}/${IFACE}.conf"
if [[ ! -r "$WG_CONF" ]]; then
    die "wg-quick config missing: $WG_CONF — see modules/vpn-bridge/README.md"
fi

changes=0

# ---------------------------------------------------------------- service
service_name="wg-quick@${IFACE}.service"
if systemctl is-enabled --quiet "$service_name" 2>/dev/null; then
    log "$service_name already enabled"
else
    run "enable $service_name" -- systemctl enable "$service_name"
    changes=$((changes + 1))
fi

if systemctl is-active --quiet "$service_name"; then
    log "$service_name already running — reload-or-restart"
    run "reload-or-restart $service_name" -- systemctl reload-or-restart "$service_name"
else
    run "start $service_name" -- systemctl start "$service_name"
    changes=$((changes + 1))
fi

# ---------------------------------------------------------------- nftables forward
HAVE_NFT_TABLE=0
if nft list table inet selfdef_vpn_bridge >/dev/null 2>&1; then
    HAVE_NFT_TABLE=1
fi

if [[ -n "$FORWARD_TO_LAN" ]]; then
    [[ "$FORWARD_TO_LAN" =~ ^[a-zA-Z0-9_-]+$ ]] || die "forward_to_lan has unsafe characters: '$FORWARD_TO_LAN'"

    TEMPLATE="$TEMPLATE_DIR/forward.rule.tmpl"
    [[ -r "$TEMPLATE" ]] || die "template missing: $TEMPLATE"
    RENDERED=$(mktemp)
    trap 'rm -f "$RENDERED"' EXIT
    sed \
        -e "s|@@WG_IFACE@@|${IFACE}|g" \
        -e "s|@@LAN_IFACE@@|${FORWARD_TO_LAN}|g" \
        "$TEMPLATE" > "$RENDERED"

    if [[ -r "$NFT_RULESET_PATH" ]] && cmp -s "$RENDERED" "$NFT_RULESET_PATH" && [[ "$HAVE_NFT_TABLE" == "1" ]]; then
        log "nftables forward rules already at target state"
    else
        run "install nftables forward rules to $NFT_RULESET_PATH" \
            -- install -D -m 0644 "$RENDERED" "$NFT_RULESET_PATH"
        run "load nftables forward rules" -- nft -f "$NFT_RULESET_PATH"
        changes=$((changes + 2))
    fi
else
    # No forwarding requested — remove any stale rules we may have set.
    if [[ "$HAVE_NFT_TABLE" == "1" ]]; then
        run "remove stale forward table (forward_to_lan unset)" \
            -- nft delete table inet selfdef_vpn_bridge
        changes=$((changes + 1))
    fi
    if [[ -f "$NFT_RULESET_PATH" ]]; then
        run "remove stale $NFT_RULESET_PATH" -- rm -f "$NFT_RULESET_PATH"
        changes=$((changes + 1))
    fi
fi

# ---------------------------------------------------------------- finalise
if [[ "$changes" -eq 0 ]]; then
    emit_status "skipped" "already at target state ($ROLE on $IFACE)"
else
    emit_status "ok" "applied $changes change(s)"
fi
