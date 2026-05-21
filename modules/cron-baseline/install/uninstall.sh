#!/usr/bin/env bash
# cron-baseline — uninstall.
#
# Restores operator's originals from .selfdef-backup if present.
# If no backup, REMOVES our cron.allow / at.allow / *.deny so
# the cron-default "everyone can crontab" behavior returns.

set -euo pipefail

MODULE="cron-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
CRON_ALLOW="${SELFDEF_CRON_ALLOW:-/etc/cron.allow}"
AT_ALLOW="${SELFDEF_AT_ALLOW:-/etc/at.allow}"
CRON_DENY="${SELFDEF_CRON_DENY:-/etc/cron.deny}"
AT_DENY="${SELFDEF_AT_DENY:-/etc/at.deny}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

restore_or_remove() {
    local dst="$1"
    local backup="${dst}.selfdef-backup"
    if [[ -f "$backup" ]]; then
        if [[ "$DRY_RUN" == "1" ]]; then
            log "DRY_RUN: would restore $backup → $dst"
        else
            run "restore $(basename "$dst")" -- mv "$backup" "$dst"
        fi
    elif [[ -f "$dst" ]]; then
        if [[ "$DRY_RUN" == "1" ]]; then
            log "DRY_RUN: would remove $dst (no backup)"
        else
            run "remove $(basename "$dst") (no backup)" -- rm -f "$dst"
        fi
    fi
}

restore_or_remove "$CRON_ALLOW"
restore_or_remove "$AT_ALLOW"
restore_or_remove "$CRON_DENY"
restore_or_remove "$AT_DENY"

emit_status "ok" "cron-baseline uninstalled (operator originals restored where backup present; cron daemon will resume default access on next read)"
