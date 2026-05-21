#!/usr/bin/env bash
# auditd-tune — uninstall.
#
# Restores the operator's original auditd.conf from the
# selfdef-backup IF the current file carries the selfdef header
# marker. If the current file does NOT carry the marker (operator
# replaced it post-install), leaves it alone.
#
# Operator can resync after manual restore via systemctl restart
# auditd.

set -euo pipefail

MODULE="auditd-tune"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if [[ ! -f "$AUDITD_CONF" ]]; then
    emit_status "ok" "auditd.conf already absent"
    exit 0
fi

if ! head -1 "$AUDITD_CONF" | grep -qF "$AUDITD_MARKER"; then
    emit_status "ok" "auditd.conf present but NOT selfdef-managed — leaving alone"
    exit 0
fi

if [[ -f "$AUDITD_BACKUP" ]]; then
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would restore $AUDITD_BACKUP → $AUDITD_CONF"
    else
        run "restore operator auditd.conf from backup" -- mv "$AUDITD_BACKUP" "$AUDITD_CONF"
    fi
else
    # No backup (fresh install where operator never had a custom
    # conf). Restore a minimal OS-default-equivalent by deleting
    # our managed file — apt/dpkg reinstall of the auditd package
    # would recreate it. For now, just remove.
    log "no backup at $AUDITD_BACKUP — removing managed auditd.conf (operator may need to reinstall auditd package to restore OS-default)"
    if [[ "$DRY_RUN" != "1" ]]; then
        rm -f "$AUDITD_CONF"
    fi
fi

if [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    systemctl restart auditd 2>/dev/null || pkill -HUP -x auditd || true
fi

emit_status "ok" "auditd-tune restored operator auditd.conf"
