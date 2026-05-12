#!/usr/bin/env bash
# suricata — check. No state changes. One JSON status line on stdout.

set -euo pipefail

MODULE="suricata"
CONFIG_FILE="${SELFDEF_SURICATA_CONFIG:-/etc/selfdef/modules/suricata.toml}"

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

MODE=$(toml_get mode "$CONFIG_FILE" || echo "nfqueue")

# Service running.
if command -v systemctl >/dev/null; then
    if ! systemctl is-active --quiet suricata.service; then
        problems+=("suricata.service not active")
    fi
fi

# NFQUEUE rule attached if we're in nfqueue mode.
if [[ "$MODE" == "nfqueue" ]] && command -v nft >/dev/null; then
    if ! nft list table inet selfdef_bridge >/dev/null 2>&1; then
        problems+=("bridge-l2 nftables table missing")
    elif ! nft -a list chain inet selfdef_bridge forward_hook 2>/dev/null \
            | grep -q 'comment "selfdef-suricata"'; then
        problems+=("NFQUEUE jump not present in forward_hook")
    fi
fi

if [[ "${#problems[@]}" -eq 0 ]]; then
    emit_status "ok" "suricata.service running ($MODE mode)"
    exit 0
else
    msg=$(IFS=';'; printf '%s' "${problems[*]}")
    emit_status "failed" "$msg"
    exit 1
fi
