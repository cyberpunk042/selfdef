#!/usr/bin/env bash
# home-perms-baseline — uninstall.
#
# Restore the pre-selfdef modes from the backup. We do NOT
# blindly loosen — we restore EXACTLY what was recorded.

set -euo pipefail

MODULE="home-perms-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if [[ -f "$BACKUP_FILE" ]]; then
    while IFS=$'\t' read -r dir uid user mode; do
        [[ -z "$dir" || ! -d "$dir" ]] && continue
        [[ "$mode" =~ ^[0-9]+$ ]] || continue
        if [[ "$DRY_RUN" == "1" ]]; then
            log "DRY_RUN: would restore $dir → $mode"
        else
            chmod "$mode" "$dir" 2>/dev/null && log "restored $dir → $mode" || true
        fi
    done < "$BACKUP_FILE"
    [[ "$DRY_RUN" != "1" ]] && rm -f "$BACKUP_FILE"
else
    log "no backup at $BACKUP_FILE — leaving current home modes in place (they are at least as tight as before)"
fi

emit_status "ok" "home-perms-baseline uninstalled (modes restored from backup where available)"
