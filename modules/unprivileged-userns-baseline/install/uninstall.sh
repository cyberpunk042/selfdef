#!/usr/bin/env bash
# unprivileged-userns-baseline — uninstall.

set -euo pipefail

MODULE="unprivileged-userns-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if [[ -f "$SYSCTL_DROPIN" ]]; then
    if head -1 "$SYSCTL_DROPIN" | grep -qF "$HEADER_MARKER"; then
        if [[ "$DRY_RUN" == "1" ]]; then
            log "DRY_RUN: would remove $SYSCTL_DROPIN"
        else
            rm -f "$SYSCTL_DROPIN"
            log "removed $SYSCTL_DROPIN"
        fi
    else
        log "$SYSCTL_DROPIN present but lacks selfdef marker — leaving in place (operator-managed)"
    fi
fi

log "live kernel.unprivileged_userns_clone NOT reverted; sysctl --system or reboot restores distro default"

emit_status "ok" "unprivileged-userns-baseline uninstalled"
