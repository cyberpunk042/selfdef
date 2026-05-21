#!/usr/bin/env bash
# bluetooth-disable — uninstall.

set -euo pipefail

MODULE="bluetooth-disable"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if command -v systemctl >/dev/null 2>&1 && [[ "$DRY_RUN" != "1" ]]; then
    for unit in "${BT_UNITS[@]}"; do
        if systemctl list-unit-files "$unit" >/dev/null 2>&1; then
            systemctl unmask "$unit" 2>/dev/null || true
            systemctl reset-failed "$unit" 2>/dev/null || true
        fi
    done
fi

# Remove modprobe blacklist ONLY if header marker confirms ownership.
if [[ -f "$MODPROBE_BLACKLIST" ]]; then
    if head -1 "$MODPROBE_BLACKLIST" | grep -qF "$HEADER_MARKER"; then
        [[ "$DRY_RUN" == "1" ]] && log "DRY_RUN: would remove $MODPROBE_BLACKLIST" || rm -f "$MODPROBE_BLACKLIST"
    else
        log "$MODPROBE_BLACKLIST present but lacks selfdef marker — leaving in place (operator-managed)"
    fi
fi

# Unblock rfkill.
if command -v rfkill >/dev/null 2>&1 && [[ "$DRY_RUN" != "1" ]]; then
    rfkill unblock bluetooth 2>/dev/null || true
fi

emit_status "ok" "bluetooth-disable uninstalled (operator runs 'modprobe btusb' + 'systemctl enable bluetooth' to re-activate; reboot required for full module reload)"
