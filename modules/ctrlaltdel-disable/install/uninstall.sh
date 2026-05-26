#!/usr/bin/env bash
# ctrlaltdel-disable — uninstall.

set -euo pipefail

MODULE="ctrlaltdel-disable"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if command -v systemctl >/dev/null 2>&1 && [[ "$DRY_RUN" != "1" ]]; then
    # Unmask the target if we masked it.
    if [[ "$(systemctl is-enabled "$CAD_TARGET" 2>/dev/null || echo)" == "masked" ]]; then
        systemctl unmask "$CAD_TARGET" 2>/dev/null || true
        log "unmasked $CAD_TARGET"
    fi
fi

# Remove the logind drop-in if it carries our marker.
if [[ -f "$LOGIND_DROPIN" ]]; then
    if head -1 "$LOGIND_DROPIN" | grep -qF "$HEADER_MARKER"; then
        [[ "$DRY_RUN" == "1" ]] && log "DRY_RUN: would remove $LOGIND_DROPIN" || { rm -f "$LOGIND_DROPIN"; log "removed $LOGIND_DROPIN"; }
        command -v systemctl >/dev/null 2>&1 && [[ "$DRY_RUN" != "1" ]] && systemctl kill -s HUP systemd-logind 2>/dev/null || true
    else
        log "$LOGIND_DROPIN present but lacks selfdef marker — leaving in place (operator-managed)"
    fi
fi

emit_status "ok" "ctrlaltdel-disable uninstalled"
