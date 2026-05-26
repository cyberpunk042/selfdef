#!/usr/bin/env bash
# coredump-suid-restrict — check. Read-only.

set -euo pipefail

MODULE="coredump-suid-restrict"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_COREDUMP_SUID_CONFIG:-/etc/selfdef/modules/coredump-suid-restrict.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "suid-only")

drift=0

if [[ ! -f "$SYSCTL_DROPIN" ]]; then
    emit_status "drift" "missing $SYSCTL_DROPIN"
    drift=$((drift + 1))
elif ! head -1 "$SYSCTL_DROPIN" | grep -qF "$HEADER_MARKER"; then
    emit_status "drift" "$SYSCTL_DROPIN exists but lacks selfdef header marker"
    drift=$((drift + 1))
fi

if command -v sysctl >/dev/null 2>&1; then
    live=$(sysctl -n fs.suid_dumpable 2>/dev/null || echo "")
    if [[ -n "$live" && "$live" != "0" ]]; then
        emit_status "drift" "fs.suid_dumpable=$live expected 0"
        drift=$((drift + 1))
    fi
fi

if [[ "$PROFILE" == "all-off" ]]; then
    if [[ ! -f "$LIMITS_DROPIN" ]]; then
        emit_status "drift" "missing $LIMITS_DROPIN (all-off requires limits.d hard-core-0)"
        drift=$((drift + 1))
    elif ! head -1 "$LIMITS_DROPIN" | grep -qF "$HEADER_MARKER"; then
        emit_status "drift" "$LIMITS_DROPIN exists but lacks selfdef header marker"
        drift=$((drift + 1))
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "coredump-suid-restrict profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "coredump-suid-restrict profile=$PROFILE no drift"
