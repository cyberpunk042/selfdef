#!/usr/bin/env bash
# unprivileged-userns-baseline — check. Read-only.

set -euo pipefail

MODULE="unprivileged-userns-baseline"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_USERNS_CONFIG:-/etc/selfdef/modules/unprivileged-userns-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "allow")
WANT=$([ "$PROFILE" == "deny" ] && echo 0 || echo 1)

drift=0
if [[ ! -f "$SYSCTL_DROPIN" ]]; then
    emit_status "drift" "missing $SYSCTL_DROPIN"
    drift=$((drift + 1))
elif ! head -1 "$SYSCTL_DROPIN" | grep -qF "$HEADER_MARKER"; then
    emit_status "drift" "$SYSCTL_DROPIN exists but lacks selfdef header marker"
    drift=$((drift + 1))
fi

if command -v sysctl >/dev/null 2>&1; then
    LIVE=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo "")
    if [[ -z "$LIVE" ]]; then
        log "kernel.unprivileged_userns_clone unreadable — kernel may lack the sysctl"
    elif [[ "$LIVE" != "$WANT" ]]; then
        emit_status "drift" "live kernel.unprivileged_userns_clone=$LIVE profile=$PROFILE expects $WANT"
        drift=$((drift + 1))
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "unprivileged-userns-baseline profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "unprivileged-userns-baseline profile=$PROFILE no drift"
