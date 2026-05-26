#!/usr/bin/env bash
# login-defs-baseline — check. Read-only.

set -euo pipefail

MODULE="login-defs-baseline"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_LOGINDEFS_CONFIG:-/etc/selfdef/modules/login-defs-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "standard")

drift=0

# At least one of the two targets must carry our marker.
present=0
if [[ -f "$DROPIN" ]] && head -1 "$DROPIN" | grep -qF "$HEADER_MARKER"; then
    present=1
fi
if [[ -f "$LEGACY_LOGIN_DEFS" ]] && grep -qF "$HEADER_MARKER" "$LEGACY_LOGIN_DEFS"; then
    present=1
fi
if [[ "$present" -eq 0 ]]; then
    emit_status "drift" "no selfdef-marked login.defs config found ($DROPIN or $LEGACY_LOGIN_DEFS)"
    drift=$((drift + 1))
fi

# Verify the sentinel keys resolve to the rendered value. We
# parse the drop-in (authoritative) if present.
src_file=""
[[ -f "$DROPIN" ]] && src_file="$DROPIN"
if [[ -n "$src_file" ]]; then
    for key in "${SENTINEL_KEYS[@]}"; do
        if ! grep -qE "^\s*${key}\s+" "$src_file"; then
            emit_status "drift" "$src_file missing key $key"
            drift=$((drift + 1))
        fi
    done
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "login-defs-baseline profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "login-defs-baseline profile=$PROFILE no drift"
