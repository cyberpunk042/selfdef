#!/usr/bin/env bash
# aslr-baseline — uninstall.

set -euo pipefail

MODULE="aslr-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if [[ -f "$SYSCTL_DROPIN" ]]; then
    if head -1 "$SYSCTL_DROPIN" | grep -qF "$HEADER_MARKER"; then
        [[ "$DRY_RUN" == "1" ]] && log "DRY_RUN: would remove $SYSCTL_DROPIN" || { rm -f "$SYSCTL_DROPIN"; log "removed $SYSCTL_DROPIN"; }
    else
        log "$SYSCTL_DROPIN present but lacks selfdef marker — leaving in place (operator-managed)"
    fi
fi

# Live value NOT reverted — most distros default to 2 anyway,
# so removing the drop-in leaves the secure default in place.
log "live kernel.randomize_va_space NOT changed; distro default (2) remains after reboot/sysctl --system"

emit_status "ok" "aslr-baseline uninstalled"
