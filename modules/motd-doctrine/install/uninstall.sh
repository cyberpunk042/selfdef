#!/usr/bin/env bash
# motd-doctrine — uninstall.
#
# Restores operator's originals from .selfdef-backup IF the
# current file is selfdef-managed (header marker check).
# Removes the verbose-profile dynamic hook.

set -euo pipefail

MODULE="motd-doctrine"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
UPDATE_MOTD_DIR="${SELFDEF_UPDATE_MOTD_DIR:-/etc/update-motd.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

restore_one() {
    local dst="$1"
    local backup="${dst}.selfdef-backup"
    if [[ ! -f "$dst" ]]; then
        return 0
    fi
    if ! head -1 "$dst" | grep -qF "$ISSUE_MARKER"; then
        log "$dst not selfdef-managed — leaving alone"
        return 0
    fi
    if [[ -f "$backup" ]]; then
        if [[ "$DRY_RUN" == "1" ]]; then
            log "DRY_RUN: would restore $backup → $dst"
        else
            run "restore $(basename "$dst")" -- mv "$backup" "$dst"
        fi
    else
        log "no backup at $backup — removing managed file $dst"
        [[ "$DRY_RUN" != "1" ]] && rm -f "$dst"
    fi
}

restore_one /etc/issue
restore_one /etc/issue.net
restore_one /etc/motd

# Remove the verbose-profile hook.
if [[ -f "${UPDATE_MOTD_DIR}/50-selfdef-presence" ]]; then
    run "remove 50-selfdef-presence" -- rm -f "${UPDATE_MOTD_DIR}/50-selfdef-presence"
fi

emit_status "ok" "motd-doctrine uninstalled (operator originals restored where backup present)"
