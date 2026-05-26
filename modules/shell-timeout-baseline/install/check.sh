#!/usr/bin/env bash
# shell-timeout-baseline — check. Read-only.

set -euo pipefail

MODULE="shell-timeout-baseline"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_TMOUT_CONFIG:-/etc/selfdef/modules/shell-timeout-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "standard")
want=900
[[ "$PROFILE" == "strict" ]] && want=300

drift=0
if [[ ! -f "$DROPIN" ]]; then
    emit_status "drift" "missing $DROPIN"
    drift=$((drift + 1))
elif ! grep -qF "$HEADER_MARKER" "$DROPIN"; then
    emit_status "drift" "$DROPIN exists but lacks selfdef header marker"
    drift=$((drift + 1))
elif ! grep -qE "TMOUT=${want}\b" "$DROPIN"; then
    emit_status "drift" "$DROPIN does not set TMOUT=${want} for profile=$PROFILE"
    drift=$((drift + 1))
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "shell-timeout-baseline profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "shell-timeout-baseline profile=$PROFILE TMOUT=${want} configured"
