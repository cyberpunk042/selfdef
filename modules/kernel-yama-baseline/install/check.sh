#!/usr/bin/env bash
# kernel-yama-baseline — check. Read-only.

set -euo pipefail

MODULE="kernel-yama-baseline"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_YAMA_CONFIG:-/etc/selfdef/modules/kernel-yama-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "relaxed")
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
    LIVE=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null || echo "")
    if [[ -z "$LIVE" ]]; then
        log "kernel.yama.ptrace_scope unreadable — yama LSM may be disabled"
    elif [[ "$LIVE" != "$WANT" ]]; then
        if [[ "$LIVE" == "3" ]]; then
            log "live ptrace_scope=3 (paranoid, kernel-locked until reboot); drop-in profile=$PROFILE will apply post-reboot"
        else
            emit_status "drift" "live ptrace_scope=$LIVE, profile=$PROFILE expects $WANT"
            drift=$((drift + 1))
        fi
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "kernel-yama-baseline profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "kernel-yama-baseline profile=$PROFILE no drift"
