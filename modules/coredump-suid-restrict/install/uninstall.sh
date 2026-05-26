#!/usr/bin/env bash
# coredump-suid-restrict — uninstall.

set -euo pipefail

MODULE="coredump-suid-restrict"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

for f in "$SYSCTL_DROPIN" "$LIMITS_DROPIN"; do
    if [[ -f "$f" ]]; then
        if head -1 "$f" | grep -qF "$HEADER_MARKER"; then
            [[ "$DRY_RUN" == "1" ]] && log "DRY_RUN: would remove $f" || { rm -f "$f"; log "removed $f"; }
        else
            log "$f present but lacks selfdef marker — leaving in place (operator-managed)"
        fi
    fi
done

log "live fs.suid_dumpable NOT reverted; reboot or 'sysctl --system' restores distro default"

emit_status "ok" "coredump-suid-restrict uninstalled"
