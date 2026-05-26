#!/usr/bin/env bash
# nftables-baseline — uninstall.

set -euo pipefail

MODULE="nftables-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

# Remove our table from the live ruleset (other tables left
# intact — we only ever managed inet selfdef_filter).
if command -v nft >/dev/null 2>&1 && [[ "$DRY_RUN" != "1" ]]; then
    nft delete table inet selfdef_filter 2>/dev/null \
        && log "removed live inet selfdef_filter table" \
        || log "inet selfdef_filter table not loaded (nothing to remove live)"
fi

# Remove the drop-in file if it carries our marker.
if [[ -f "$NFT_DROPIN" ]]; then
    if head -1 "$NFT_DROPIN" | grep -qF "$HEADER_MARKER"; then
        [[ "$DRY_RUN" == "1" ]] && log "DRY_RUN: would remove $NFT_DROPIN" || { rm -f "$NFT_DROPIN"; log "removed $NFT_DROPIN"; }
    else
        log "$NFT_DROPIN present but lacks selfdef marker — leaving in place (operator-managed)"
    fi
fi

log "NOTE: removing the firewall leaves the host with NO selfdef default-deny. The operator's prior ruleset backup is at $BACKUP_FILE if a restore is wanted."

emit_status "ok" "nftables-baseline uninstalled (selfdef_filter table removed; host firewall posture reverts to whatever else is loaded)"
