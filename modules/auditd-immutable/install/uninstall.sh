#!/usr/bin/env bash
# auditd-immutable — uninstall.
#
# Removes the 99-selfdef-immutable.rules file. If the live
# state is `-e 2`, it STAYS THAT WAY until reboot (kernel
# immutability is sealed-until-reboot by design). Operator
# reboots to fully revert.

set -euo pipefail

MODULE="auditd-immutable"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
RULES_D="${SELFDEF_AUDIT_RULES_D:-/etc/audit/rules.d}"
DST="${RULES_D}/99-selfdef-immutable.rules"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

removed=0
if [[ -f "$DST" ]]; then
    run "remove $(basename "$DST")" -- rm -f "$DST"
    removed=$((removed + 1))
fi

# Detect live state for operator-readable note.
if command -v auditctl >/dev/null 2>&1; then
    live_e=$(auditctl -s 2>/dev/null | awk -F': *' '/^enabled/ {print $2; exit}' || echo "?")
    log "live audit enabled=$live_e"
    if [[ "$live_e" == "2" ]]; then
        log "NOTE: kernel audit is still IMMUTABLE in the live ring. File removed; reboot to fully revert to mutable state."
    fi
fi

emit_status "ok" "auditd-immutable removed=$removed (NOTE: live -e 2 state requires reboot to undo)"
