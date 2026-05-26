#!/usr/bin/env bash
# shell-timeout-baseline — uninstall.

set -euo pipefail

MODULE="shell-timeout-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if [[ -f "$DROPIN" ]]; then
    if grep -qF "$HEADER_MARKER" "$DROPIN"; then
        [[ "$DRY_RUN" == "1" ]] && log "DRY_RUN: would remove $DROPIN" || { rm -f "$DROPIN"; log "removed $DROPIN"; }
    else
        log "$DROPIN present but lacks selfdef marker — leaving in place (operator-managed)"
    fi
fi

log "TMOUT removed for NEW shells; existing sessions keep their readonly TMOUT until logout"

emit_status "ok" "shell-timeout-baseline uninstalled"
