#!/usr/bin/env bash
# file-protections-baseline — check. Read-only.

set -euo pipefail

MODULE="file-protections-baseline"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_FILEPROT_CONFIG:-/etc/selfdef/modules/file-protections-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "baseline")

drift=0
if [[ ! -f "$SYSCTL_DROPIN" ]]; then
    emit_status "drift" "missing $SYSCTL_DROPIN"
    drift=$((drift + 1))
elif ! head -1 "$SYSCTL_DROPIN" | grep -qF "$HEADER_MARKER"; then
    emit_status "drift" "$SYSCTL_DROPIN exists but lacks selfdef header marker"
    drift=$((drift + 1))
fi

if command -v sysctl >/dev/null 2>&1; then
    for kv in "${SENTINEL_KEYS[@]}"; do
        key="${kv%%:*}"; want="${kv##*:}"
        got=$(sysctl -n "$key" 2>/dev/null || echo "")
        if [[ -z "$got" ]]; then
            log "sysctl key '$key' unreadable (kernel lacks the option?)"
            continue
        fi
        if [[ "$got" != "$want" ]]; then
            emit_status "drift" "$key=$got expected=$want"
            drift=$((drift + 1))
        fi
    done
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "file-protections-baseline profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "file-protections-baseline profile=$PROFILE no drift"
