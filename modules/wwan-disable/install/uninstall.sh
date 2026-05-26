#!/usr/bin/env bash
# wwan-disable — uninstall.

set -euo pipefail

MODULE="wwan-disable"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

# Unmask ModemManager.
if command -v systemctl >/dev/null 2>&1 && [[ "$DRY_RUN" != "1" ]]; then
    for unit in "${MM_UNITS[@]}"; do
        systemctl list-unit-files "$unit" >/dev/null 2>&1 || continue
        systemctl unmask "$unit" 2>/dev/null || true
        systemctl reset-failed "$unit" 2>/dev/null || true
    done
fi

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
    rfkill unblock wwan 2>/dev/null || true
fi

log "wwan rfkill-unblocked + ModemManager unmasked; if mask profile was used, reboot to fully restore modem drivers"

emit_status "ok" "wwan-disable uninstalled"
