#!/usr/bin/env bash
# sysctl-network-baseline — uninstall.

set -euo pipefail

MODULE="sysctl-network-baseline"
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

# Note: we do NOT roll back the live runtime sysctl values. The
# next reboot OR explicit `sysctl --system` will restore distro
# defaults from the remaining /etc/sysctl.d/* files. Operator
# may run `sysctl --system` immediately if desired.
if command -v sysctl >/dev/null 2>&1 && [[ "$DRY_RUN" != "1" ]]; then
    log "live sysctl values NOT reverted; operator can run 'sudo sysctl --system' or reboot"
fi

emit_status "ok" "sysctl-network-baseline uninstalled (drop-in removed; live values persist until reboot/sysctl --system)"
