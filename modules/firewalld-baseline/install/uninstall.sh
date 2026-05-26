#!/usr/bin/env bash
# firewalld-baseline — uninstall.
#
# Restore the operator's prior default zone, then remove the
# selfdef zone. We restore-then-remove so there's never a
# window with no default zone.

set -euo pipefail

MODULE="firewalld-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if ! command -v firewall-cmd >/dev/null 2>&1; then
    emit_status "ok" "firewalld-baseline uninstalled (firewalld unavailable)"
    exit 0
fi

prior="public"
[[ -f "$BACKUP_FILE" ]] && prior=$(cat "$BACKUP_FILE" 2>/dev/null || echo "public")

if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: would restore default zone → $prior, then remove zone $SELFDEF_ZONE"
    emit_status "ok" "firewalld-baseline DRY_RUN uninstall"
    exit 0
fi

# Restore prior default zone first (no-window).
firewall-cmd --set-default-zone="$prior" >/dev/null 2>&1 \
    && log "restored default zone → $prior" \
    || log "WARN: could not restore default zone to $prior"

# Now remove our zone.
if firewall-cmd --permanent --get-zones 2>/dev/null | tr ' ' '\n' | grep -qx "$SELFDEF_ZONE"; then
    firewall-cmd --permanent --delete-zone="$SELFDEF_ZONE" >/dev/null 2>&1 || true
    log "removed permanent zone $SELFDEF_ZONE"
fi

firewall-cmd --reload >/dev/null 2>&1 || true

emit_status "ok" "firewalld-baseline uninstalled (default zone restored to $prior; selfdef zone removed)"
