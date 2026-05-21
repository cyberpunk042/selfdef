#!/usr/bin/env bash
# usbguard — uninstall.
#
# Removes the selfdef-managed rules.conf + daemon drop-in. Leaves
# the operator-baseline file alone (operator may want to reinstall
# later). Restarts the daemon so the current ruleset reflects what
# remains on disk (or stops it if no rules.conf is left).
#
# SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="usbguard"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
RULES_DST="${SELFDEF_USBGUARD_RULES_FILE:-/etc/usbguard/rules.conf}"
DAEMON_DROPIN="${SELFDEF_USBGUARD_DROPIN:-/etc/usbguard/usbguard-daemon.conf.d/50-selfdef.conf}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

removed=0

# Only delete rules.conf if it carries our header marker — never
# touch an operator-hand-edited file.
if [[ -f "$RULES_DST" ]] && grep -q "^# === selfdef usbguard rules.conf" "$RULES_DST"; then
    run "remove $(basename "$RULES_DST")" -- rm -f "$RULES_DST"
    removed=$((removed + 1))
fi

if [[ -f "$DAEMON_DROPIN" ]]; then
    run "remove $(basename "$DAEMON_DROPIN")" -- rm -f "$DAEMON_DROPIN"
    removed=$((removed + 1))
fi

if [[ "$removed" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    run "restart usbguard.service" -- systemctl restart usbguard.service || true
fi

emit_status "ok" "usbguard removed=$removed (operator-baseline at /etc/selfdef/usbguard/ preserved)"
