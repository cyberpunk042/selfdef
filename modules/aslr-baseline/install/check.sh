#!/usr/bin/env bash
# aslr-baseline — check. Read-only.

set -euo pipefail

MODULE="aslr-baseline"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_ASLR_CONFIG:-/etc/selfdef/modules/aslr-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

drift=0
if [[ ! -f "$SYSCTL_DROPIN" ]]; then
    emit_status "drift" "missing $SYSCTL_DROPIN"
    drift=$((drift + 1))
elif ! head -1 "$SYSCTL_DROPIN" | grep -qF "$HEADER_MARKER"; then
    emit_status "drift" "$SYSCTL_DROPIN exists but lacks selfdef header marker"
    drift=$((drift + 1))
fi

if command -v sysctl >/dev/null 2>&1; then
    live=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "")
    if [[ -n "$live" && "$live" != "2" ]]; then
        emit_status "drift" "kernel.randomize_va_space=$live expected 2 (full ASLR)"
        drift=$((drift + 1))
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "aslr-baseline drift=$drift"
    exit 1
fi
emit_status "ok" "aslr-baseline full ASLR, no drift"
