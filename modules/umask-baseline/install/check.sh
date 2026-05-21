#!/usr/bin/env bash
# umask-baseline — check. Read-only.

set -euo pipefail

MODULE="umask-baseline"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_UMASK_CONFIG:-/etc/selfdef/modules/umask-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
PROFILE_D="${SELFDEF_PROFILE_D:-/etc/profile.d}"
LOGIN_DEFS_D="${SELFDEF_LOGIN_DEFS_D:-/etc/login.defs.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "group")

drift=0
[[ -f "${PROFILE_D}/50-selfdef-umask.sh" ]] || { emit_status "drift" "50-selfdef-umask.sh missing"; drift=$((drift + 1)); }
[[ -f "${LOGIN_DEFS_D}/50-selfdef-umask.conf" ]] || { emit_status "drift" "50-selfdef-umask.conf missing"; drift=$((drift + 1)); }

# Live check: current shell's umask. NOT authoritative — current
# shell may pre-date the apply; but useful for operator-readable
# context.
current_umask=$(umask)
log "current shell umask: $current_umask (NOTE: takes effect on next shell)"

case "$PROFILE" in
    group)
        if ! grep -q "umask 0027" "${PROFILE_D}/50-selfdef-umask.sh" 2>/dev/null; then
            emit_status "drift" "profile.d file does not contain 'umask 0027'"
            drift=$((drift + 1))
        fi
        ;;
    strict)
        if ! grep -q "umask 0077" "${PROFILE_D}/50-selfdef-umask.sh" 2>/dev/null; then
            emit_status "drift" "profile.d file does not contain 'umask 0077'"
            drift=$((drift + 1))
        fi
        ;;
esac

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "umask-baseline profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "umask-baseline profile=$PROFILE no drift"
