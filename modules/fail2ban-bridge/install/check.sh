#!/usr/bin/env bash
# fail2ban-bridge — check. Read-only.

set -euo pipefail

MODULE="fail2ban-bridge"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_FAIL2BAN_CONFIG:-/etc/selfdef/modules/fail2ban-bridge.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
JAIL_D="${SELFDEF_FAIL2BAN_JAIL_D:-/etc/fail2ban/jail.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "standard")

drift=0
[[ -f "${JAIL_D}/50-selfdef.conf" ]] || { emit_status "drift" "50-selfdef.conf missing"; drift=$((drift + 1)); }

if [[ "$PROFILE" == "broad" ]]; then
    [[ -f "${JAIL_D}/60-selfdef-recidive.conf" ]] || { emit_status "drift" "60-selfdef-recidive.conf missing (broad profile requires it)"; drift=$((drift + 1)); }
fi

# Service active.
if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet fail2ban; then
        log "fail2ban.service NOT active"
    fi
fi

# Best-effort live status — which jails are running + how many
# IPs currently banned in total.
if command -v fail2ban-client >/dev/null 2>&1; then
    if status=$(fail2ban-client status 2>/dev/null); then
        jails=$(echo "$status" | awk -F': ' '/Jail list/ {print $2; exit}')
        log "fail2ban active jails: ${jails:-<none>}"
        # Per-jail ban count (best-effort).
        total_banned=0
        for j in $(echo "$jails" | tr ',' ' '); do
            jail=$(echo "$j" | tr -d ' ')
            [[ -z "$jail" ]] && continue
            n=$(fail2ban-client status "$jail" 2>/dev/null | awk -F': ' '/Currently banned/ {print $2; exit}')
            n="${n:-0}"
            total_banned=$((total_banned + n))
        done
        log "fail2ban currently banned IPs (across all jails): $total_banned"
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "fail2ban-bridge profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "fail2ban-bridge profile=$PROFILE no drift"
