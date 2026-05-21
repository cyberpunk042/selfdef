#!/usr/bin/env bash
# file-protections-baseline — uninstall.

set -euo pipefail

MODULE="file-protections-baseline"
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

log "live sysctl values NOT reverted; modern kernels default these ON regardless"

emit_status "ok" "file-protections-baseline uninstalled"
