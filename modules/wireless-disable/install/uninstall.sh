#!/usr/bin/env bash
# wireless-disable — uninstall.

set -euo pipefail

MODULE="wireless-disable"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

# Remove the modprobe blacklist if it carries our marker.
if [[ -f "$MODPROBE_FILE" ]]; then
    if head -1 "$MODPROBE_FILE" | grep -qF "$HEADER_MARKER"; then
        [[ "$DRY_RUN" == "1" ]] && log "DRY_RUN: would remove $MODPROBE_FILE" || { rm -f "$MODPROBE_FILE"; log "removed $MODPROBE_FILE"; }
    else
        log "$MODPROBE_FILE present but lacks selfdef marker — leaving in place (operator-managed)"
    fi
fi

# Unblock rfkill.
if command -v rfkill >/dev/null 2>&1 && [[ "$DRY_RUN" != "1" ]]; then
    rfkill unblock wifi 2>/dev/null || true
fi

log "wifi rfkill-unblocked; if mask profile was used, reboot (or modprobe the drivers) to fully restore Wi-Fi"

emit_status "ok" "wireless-disable uninstalled"
