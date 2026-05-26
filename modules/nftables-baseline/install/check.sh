#!/usr/bin/env bash
# nftables-baseline — check. Read-only.

set -euo pipefail

MODULE="nftables-baseline"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_NFT_CONFIG:-/etc/selfdef/modules/nftables-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "baseline")

drift=0

if [[ ! -f "$NFT_DROPIN" ]]; then
    emit_status "drift" "missing $NFT_DROPIN"
    drift=$((drift + 1))
elif ! head -1 "$NFT_DROPIN" | grep -qF "$HEADER_MARKER"; then
    emit_status "drift" "$NFT_DROPIN exists but lacks selfdef header marker"
    drift=$((drift + 1))
fi

# Is our table actually loaded live?
if command -v nft >/dev/null 2>&1; then
    if nft list table inet selfdef_filter >/dev/null 2>&1; then
        policy=$(nft list chain inet selfdef_filter input 2>/dev/null | awk '/policy/{print $NF}' | tr -d ';')
        log "selfdef_filter loaded; input policy=$policy"
        if [[ "$policy" != "drop" ]]; then
            emit_status "drift" "input chain policy is '$policy', expected drop"
            drift=$((drift + 1))
        fi
        # Anti-lockout sanity: an SSH accept must be present.
        if ! nft list chain inet selfdef_filter input 2>/dev/null | grep -qE 'tcp dport.*22'; then
            emit_status "drift" "loaded ruleset lacks SSH(22) accept — lockout risk"
            drift=$((drift + 1))
        fi
    else
        emit_status "drift" "selfdef_filter table NOT loaded live"
        drift=$((drift + 1))
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "nftables-baseline profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "nftables-baseline profile=$PROFILE loaded + default-deny + SSH allowed"
