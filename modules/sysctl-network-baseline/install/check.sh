#!/usr/bin/env bash
# sysctl-network-baseline — check. Read-only.

set -euo pipefail

MODULE="sysctl-network-baseline"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_SYSCTL_NETWORK_CONFIG:-/etc/selfdef/modules/sysctl-network-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "baseline")

drift=0

# 1. Drop-in file present + has selfdef header marker.
if [[ ! -f "$SYSCTL_DROPIN" ]]; then
    emit_status "drift" "missing $SYSCTL_DROPIN"
    drift=$((drift + 1))
elif ! head -1 "$SYSCTL_DROPIN" | grep -qF "$HEADER_MARKER"; then
    emit_status "drift" "$SYSCTL_DROPIN exists but lacks selfdef header marker"
    drift=$((drift + 1))
fi

# 2. Live sysctl sentinel values match expectation for profile.
if command -v sysctl >/dev/null 2>&1; then
    case "$PROFILE" in
        baseline) keys=("${SENTINEL_KEYS_BASELINE[@]}") ;;
        router)   keys=("${SENTINEL_KEYS_ROUTER[@]}") ;;
        paranoid) keys=("${SENTINEL_KEYS_PARANOID[@]}") ;;
    esac
    for kv in "${keys[@]}"; do
        key="${kv%%:*}"; want="${kv##*:}"
        got=$(sysctl -n "$key" 2>/dev/null || echo "")
        if [[ -z "$got" ]]; then
            log "sysctl key '$key' unreadable on this host (namespace-restricted)"
            continue
        fi
        if [[ "$got" != "$want" ]]; then
            emit_status "drift" "$key=$got expected=$want"
            drift=$((drift + 1))
        fi
    done
else
    log "sysctl unavailable — cannot verify runtime values"
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "sysctl-network-baseline profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "sysctl-network-baseline profile=$PROFILE no drift"
