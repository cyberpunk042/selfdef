#!/usr/bin/env bash
# login-defs-baseline — uninstall.

set -euo pipefail

MODULE="login-defs-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

# Remove the drop-in.
if [[ -f "$DROPIN" ]]; then
    if head -1 "$DROPIN" | grep -qF "$HEADER_MARKER"; then
        [[ "$DRY_RUN" == "1" ]] && log "DRY_RUN: would remove $DROPIN" || { rm -f "$DROPIN"; log "removed $DROPIN"; }
    else
        log "$DROPIN present but lacks selfdef marker — leaving in place (operator-managed)"
    fi
fi

# Strip the marker-fenced block from legacy /etc/login.defs.
if [[ -f "$LEGACY_LOGIN_DEFS" ]] && grep -qF "$HEADER_MARKER" "$LEGACY_LOGIN_DEFS"; then
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would strip selfdef block from $LEGACY_LOGIN_DEFS"
    else
        sed -i "/$HEADER_MARKER/,/# end-selfdef login-defs-baseline/d" "$LEGACY_LOGIN_DEFS" 2>/dev/null || true
        log "stripped selfdef block from $LEGACY_LOGIN_DEFS"
    fi
fi

log "NOTE: existing accounts keep their current aging; operator re-applies via 'chage' if desired"

emit_status "ok" "login-defs-baseline uninstalled"
