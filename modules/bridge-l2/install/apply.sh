#!/usr/bin/env bash
# bridge-l2 — apply.
#
# Idempotent: re-running on a host already at the target state is a no-op.
# Dry-run aware: SELFDEF_DRY_RUN=1 prints intended changes only.
# Emits one JSON status line on stdout at the end.
#
# Config is read from /etc/selfdef/modules/bridge-l2.toml (rendered by
# `selfdefctl modules apply` from defaults + profile + host overrides),
# or stdin if BRIDGE_L2_CONFIG_FROM_STDIN=1.

set -euo pipefail

MODULE="bridge-l2"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_BRIDGE_L2_CONFIG:-/etc/selfdef/modules/bridge-l2.toml}"
TEMPLATE_DIR="${SELFDEF_BRIDGE_L2_TEMPLATES:-/usr/share/selfdef/modules/bridge-l2/templates}"
NFT_RULESET_PATH="/etc/nftables.d/selfdef-bridge.conf"

# ---------------------------------------------------------------- helpers
# Shared (log/emit_status/die/run/toml_get) + module-specific
# (toml_get_list).
# shellcheck source=lib.sh
source "${BASH_SOURCE[0]%/*}/lib.sh"

# ---------------------------------------------------------------- preflight
[[ -r "$CONFIG_FILE" ]] || die "config file not readable: $CONFIG_FILE"
command -v ip >/dev/null || die "ip(8) missing"
command -v nft >/dev/null || die "nft(8) missing"

BRIDGE_NAME=$(toml_get bridge_name "$CONFIG_FILE" || echo "br0")
FORWARD_POLICY=$(toml_get forward_policy "$CONFIG_FILE" || echo "accept")
MGMT_IFACE=$(toml_get management_iface "$CONFIG_FILE" || echo "")
MEMBERS=$(toml_get_list members "$CONFIG_FILE")

[[ -n "$BRIDGE_NAME" ]] || die "bridge_name is empty in $CONFIG_FILE"
[[ "$FORWARD_POLICY" == "accept" || "$FORWARD_POLICY" == "drop" ]] \
    || die "forward_policy must be accept|drop, got '$FORWARD_POLICY'"
[[ -n "$MEMBERS" ]] || die "members list is empty — at least one NIC is required"

# ---------------------------------------------------------------- bridge
changes=0

bridge_exists() { ip link show dev "$1" type bridge >/dev/null 2>&1; }
member_of()     { [[ "$(ip -o link show "$1" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="master") print $(i+1)}')" == "$2" ]]; }
link_up()       { ip -o link show "$1" 2>/dev/null | grep -q "state UP"; }

if bridge_exists "$BRIDGE_NAME"; then
    log "bridge $BRIDGE_NAME already present"
else
    run "create bridge $BRIDGE_NAME" -- ip link add name "$BRIDGE_NAME" type bridge
    changes=$((changes + 1))
fi

while IFS= read -r iface; do
    [[ -z "$iface" ]] && continue
    if member_of "$iface" "$BRIDGE_NAME"; then
        log "$iface already enslaved to $BRIDGE_NAME"
    else
        run "enslave $iface to $BRIDGE_NAME" -- ip link set "$iface" master "$BRIDGE_NAME"
        changes=$((changes + 1))
    fi
    if ! link_up "$iface"; then
        run "bring up $iface" -- ip link set "$iface" up
        changes=$((changes + 1))
    fi
done <<< "$MEMBERS"

if ! link_up "$BRIDGE_NAME"; then
    run "bring up $BRIDGE_NAME" -- ip link set "$BRIDGE_NAME" up
    changes=$((changes + 1))
fi

# ---------------------------------------------------------------- nftables
TEMPLATE="$TEMPLATE_DIR/nftables.conf.tmpl"
[[ -r "$TEMPLATE" ]] || die "template missing: $TEMPLATE"

if [[ -n "$MGMT_IFACE" ]]; then
    MGMT_RULE="iifname \"$MGMT_IFACE\" ct state new drop"
else
    MGMT_RULE="# (no management_iface configured)"
fi

RENDERED=$(mktemp)
trap 'rm -f "$RENDERED"' EXIT
sed \
    -e "s|@@BRIDGE_NAME@@|${BRIDGE_NAME}|g" \
    -e "s|@@FORWARD_POLICY@@|${FORWARD_POLICY}|g" \
    -e "s|@@MGMT_INPUT_RULE@@|${MGMT_RULE}|g" \
    "$TEMPLATE" > "$RENDERED"

if [[ -r "$NFT_RULESET_PATH" ]] && cmp -s "$RENDERED" "$NFT_RULESET_PATH"; then
    log "nftables ruleset already at target state"
else
    run "install nftables ruleset to $NFT_RULESET_PATH" -- install -D -m 0644 "$RENDERED" "$NFT_RULESET_PATH"
    run "load nftables ruleset" -- nft -f "$NFT_RULESET_PATH"
    changes=$((changes + 2))
fi

# ---------------------------------------------------------------- finalise
if [[ "$changes" -eq 0 ]]; then
    emit_status "skipped" "already at target state"
else
    emit_status "ok" "applied $changes change(s)"
fi
