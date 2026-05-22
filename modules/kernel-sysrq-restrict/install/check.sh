#!/usr/bin/env bash
# kernel-sysrq-restrict — check. Read-only.

set -euo pipefail

MODULE="kernel-sysrq-restrict"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_SYSRQ_CONFIG:-/etc/selfdef/modules/kernel-sysrq-restrict.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "off")
WANT=$(profile_to_value "$PROFILE")

drift=0
if [[ ! -f "$SYSCTL_DROPIN" ]]; then
    emit_status "drift" "missing $SYSCTL_DROPIN"
    drift=$((drift + 1))
elif ! head -1 "$SYSCTL_DROPIN" | grep -qF "$HEADER_MARKER"; then
    emit_status "drift" "$SYSCTL_DROPIN exists but lacks selfdef header marker"
    drift=$((drift + 1))
fi

if command -v sysctl >/dev/null 2>&1; then
    LIVE=$(sysctl -n kernel.sysrq 2>/dev/null || echo "")
    if [[ -z "$LIVE" ]]; then
        log "kernel.sysrq unreadable (CONFIG_MAGIC_SYSRQ=n?)"
    elif [[ "$LIVE" != "$WANT" ]]; then
        emit_status "drift" "live kernel.sysrq=$LIVE profile=$PROFILE expects $WANT"
        drift=$((drift + 1))
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "kernel-sysrq-restrict profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "kernel-sysrq-restrict profile=$PROFILE no drift"
