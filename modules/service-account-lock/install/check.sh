#!/usr/bin/env bash
# service-account-lock — check. Read-only.

set -euo pipefail

MODULE="service-account-lock"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_SVC_ACCOUNT_CONFIG:-/etc/selfdef/modules/service-account-lock.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "audit")
reserved_uids=$(toml_get reserved_uids "$CONFIG_FILE" || echo "0,1,2,3")

declare -A RESERVED
for uid in $(echo "$reserved_uids" | tr ',' ' '); do
    uid="${uid// /}"
    [[ -n "$uid" ]] && RESERVED["$uid"]=1
done

drift=0
unlocked=0
while IFS=: read -r username _ uid _ _ _ shell; do
    [[ -z "$username" ]] && continue
    [[ "$uid" -ge 1000 ]] && continue
    [[ -n "${RESERVED[$uid]:-}" ]] && continue
    if is_interactive_shell "$shell"; then
        unlocked=$((unlocked + 1))
        log "still-unlocked service account: $username (uid=$uid) shell=$shell"
    fi
done < /etc/passwd

case "$PROFILE" in
    audit)
        log "audit profile: $unlocked service account(s) with interactive shells"
        ;;
    enforce)
        if [[ "$unlocked" -gt 0 ]]; then
            emit_status "drift" "enforce profile: $unlocked service account(s) STILL have interactive shells — apply.sh may not have run or accounts were re-edited"
            drift=$((drift + 1))
        fi
        ;;
esac

if [[ -f "$ORIGINAL_LOG" ]]; then
    recorded=$(grep -v '^#' "$ORIGINAL_LOG" 2>/dev/null | grep -v '^$' | wc -l)
    log "recorded original-shell entries: $recorded"
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "service-account-lock profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "service-account-lock profile=$PROFILE unlocked=$unlocked"
