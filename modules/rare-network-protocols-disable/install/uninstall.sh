#!/usr/bin/env bash
# rare-network-protocols-disable — uninstall.

set -euo pipefail

MODULE="rare-network-protocols-disable"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if [[ -f "$MODPROBE_FILE" ]]; then
    if head -1 "$MODPROBE_FILE" | grep -qF "$HEADER_MARKER"; then
        if [[ "$DRY_RUN" == "1" ]]; then
            log "DRY_RUN: would remove $MODPROBE_FILE"
        else
            rm -f "$MODPROBE_FILE"
            log "removed $MODPROBE_FILE"
        fi
    else
        log "$MODPROBE_FILE present but lacks selfdef marker — leaving in place (operator-managed)"
    fi
fi

emit_status "ok" "rare-network-protocols-disable uninstalled"
