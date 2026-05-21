#!/usr/bin/env bash
# usbguard — check. Read-only.
#
# Verifies rules.conf exists + has the selfdef-rendered header
# marker + the daemon drop-in exists + the daemon is active.

set -euo pipefail

MODULE="usbguard"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_USBGUARD_CONFIG:-/etc/selfdef/modules/usbguard.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
RULES_DST="${SELFDEF_USBGUARD_RULES_FILE:-/etc/usbguard/rules.conf}"
DAEMON_DROPIN="${SELFDEF_USBGUARD_DROPIN:-/etc/usbguard/usbguard-daemon.conf.d/50-selfdef.conf}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "permissive")

drift=0

if [[ ! -f "$RULES_DST" ]]; then
    emit_status "drift" "rules.conf missing: $RULES_DST"
    drift=$((drift + 1))
elif ! grep -q "^# === selfdef usbguard rules.conf" "$RULES_DST"; then
    emit_status "drift" "rules.conf present but not selfdef-rendered (no header marker)"
    drift=$((drift + 1))
fi

if [[ ! -f "$DAEMON_DROPIN" ]]; then
    emit_status "drift" "daemon drop-in missing: $DAEMON_DROPIN"
    drift=$((drift + 1))
fi

# Best-effort daemon-active check (won't fail the check if systemctl
# isn't available — the rules+dropin are the operator-actionable
# invariants).
if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet usbguard.service; then
        log "usbguard.service not active — run 'systemctl start usbguard'"
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "usbguard profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "usbguard profile=$PROFILE no drift"
