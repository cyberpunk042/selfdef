#!/usr/bin/env bash
# kernel-yama-baseline — uninstall.

set -euo pipefail

MODULE="kernel-yama-baseline"
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

# Live value NOT reverted. If it was paranoid=3, even sysctl
# --system cannot lower it (kernel-locked) until reboot.
log "live kernel.yama.ptrace_scope NOT reverted; operator can run 'sudo sysctl --system' or reboot"

emit_status "ok" "kernel-yama-baseline uninstalled (drop-in removed; live value persists until reboot/sysctl --system)"
