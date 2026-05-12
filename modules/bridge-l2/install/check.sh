#!/usr/bin/env bash
# bridge-l2 — check.
#
# Exits 0 if the module is correctly installed and configured; non-zero
# otherwise. No state-changing operations. Output: one JSON status line
# on stdout, regardless of exit code.

set -euo pipefail

MODULE="bridge-l2"
CONFIG_FILE="${SELFDEF_BRIDGE_L2_CONFIG:-/etc/selfdef/modules/bridge-l2.toml}"
NFT_RULESET_PATH="/etc/nftables.d/selfdef-bridge.conf"

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

toml_get_list() {
    local key="$1" file="$2"
    local line
    line=$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$file" | head -1 || true)
    [[ -z "$line" ]] && return 0
    line="${line#*=}"; line="${line## }"
    line="${line#\[}"; line="${line%\]}"
    local IFS=','
    for tok in $line; do
        tok="${tok## }"; tok="${tok%% }"
        tok="${tok%\"}"; tok="${tok#\"}"
        [[ -n "$tok" ]] && printf '%s\n' "$tok"
    done
}

problems=()

if [[ ! -r "$CONFIG_FILE" ]]; then
    emit_status "failed" "config file not readable: $CONFIG_FILE"
    exit 1
fi

BRIDGE_NAME=$(toml_get bridge_name "$CONFIG_FILE" || echo "br0")
MEMBERS=$(toml_get_list members "$CONFIG_FILE")

# Bridge exists and is up.
if ! ip link show dev "$BRIDGE_NAME" type bridge >/dev/null 2>&1; then
    problems+=("bridge $BRIDGE_NAME not present")
elif ! ip -o link show "$BRIDGE_NAME" | grep -q "state UP"; then
    problems+=("bridge $BRIDGE_NAME not up")
fi

# Every configured member is enslaved.
while IFS= read -r iface; do
    [[ -z "$iface" ]] && continue
    master=$(ip -o link show "$iface" 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i=="master") print $(i+1)}')
    if [[ "$master" != "$BRIDGE_NAME" ]]; then
        problems+=("$iface not enslaved to $BRIDGE_NAME (master=$master)")
    fi
done <<< "$MEMBERS"

# nftables ruleset present.
if [[ ! -r "$NFT_RULESET_PATH" ]]; then
    problems+=("nftables ruleset missing at $NFT_RULESET_PATH")
fi

# nftables table loaded.
if command -v nft >/dev/null; then
    if ! nft list table inet selfdef_bridge >/dev/null 2>&1; then
        problems+=("nftables table inet selfdef_bridge not loaded")
    fi
fi

if [[ "${#problems[@]}" -eq 0 ]]; then
    emit_status "ok" "bridge $BRIDGE_NAME up; nftables ruleset loaded"
    exit 0
else
    msg=$(IFS=';'; printf '%s' "${problems[*]}")
    emit_status "failed" "$msg"
    exit 1
fi
