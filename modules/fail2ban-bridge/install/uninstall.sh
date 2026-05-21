#!/usr/bin/env bash
# fail2ban-bridge — uninstall.
#
# Removes only the selfdef jail.d drop-ins. PRESERVES the
# OS-shipped /etc/fail2ban/jail.conf + operator-extension drop-
# ins (60-operator-allow, 99-operator-*).
#
# Reloads fail2ban so the removed jails go inactive.

set -euo pipefail

MODULE="fail2ban-bridge"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
JAIL_D="${SELFDEF_FAIL2BAN_JAIL_D:-/etc/fail2ban/jail.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

removed=0
for f in "${JAIL_D}/50-selfdef.conf" \
         "${JAIL_D}/60-selfdef-recidive.conf"; do
    if [[ -f "$f" ]]; then
        run "remove $(basename "$f")" -- rm -f "$f"
        removed=$((removed + 1))
    fi
done

if [[ "$removed" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v fail2ban-client >/dev/null; then
    run "fail2ban-client reload" -- fail2ban-client reload || true
fi

emit_status "ok" "fail2ban-bridge removed=$removed (NOTE: existing bans persist in fail2ban state; manual fail2ban-client unban --all to clear)"
