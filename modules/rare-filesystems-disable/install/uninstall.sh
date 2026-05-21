#!/usr/bin/env bash
# rare-filesystems-disable — uninstall.

set -euo pipefail

MODULE="rare-filesystems-disable"
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

log "blacklist removed; modules become loadable on next modprobe attempt or boot"

emit_status "ok" "rare-filesystems-disable uninstalled"
