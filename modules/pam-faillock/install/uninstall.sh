#!/usr/bin/env bash
# pam-faillock — uninstall.
#
# Restores operator's original faillock.conf from .selfdef-backup
# IF the current file is selfdef-managed (header marker check).
# Does NOT remove /var/lib/faillock (operator-collected lockout
# state preserved).

set -euo pipefail

MODULE="pam-faillock"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if [[ ! -f "$FAILLOCK_CONF" ]]; then
    emit_status "ok" "faillock.conf already absent"
    exit 0
fi

if ! head -1 "$FAILLOCK_CONF" | grep -qF "$FAILLOCK_MARKER"; then
    emit_status "ok" "faillock.conf present but NOT selfdef-managed — leaving alone"
    exit 0
fi

if [[ -f "$FAILLOCK_BACKUP" ]]; then
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would restore $FAILLOCK_BACKUP → $FAILLOCK_CONF"
    else
        run "restore operator faillock.conf" -- mv "$FAILLOCK_BACKUP" "$FAILLOCK_CONF"
    fi
else
    log "no backup at $FAILLOCK_BACKUP — removing managed faillock.conf"
    if [[ "$DRY_RUN" != "1" ]]; then
        rm -f "$FAILLOCK_CONF"
    fi
fi

emit_status "ok" "pam-faillock restored operator faillock.conf (lockout state at /var/lib/faillock preserved)"
