#!/usr/bin/env bash
# ctrlaltdel-disable — check. Read-only.

set -euo pipefail

MODULE="ctrlaltdel-disable"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_CAD_CONFIG:-/etc/selfdef/modules/ctrlaltdel-disable.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "mask")

drift=0

if ! command -v systemctl >/dev/null 2>&1; then
    emit_status "ok" "ctrlaltdel-disable (systemctl unavailable)"
    exit 0
fi

if [[ "$PROFILE" == "mask" ]]; then
    state=$(systemctl is-enabled "$CAD_TARGET" 2>/dev/null || echo "")
    if [[ "$state" != "masked" ]]; then
        emit_status "drift" "$CAD_TARGET is '$state' — mask profile requires masked"
        drift=$((drift + 1))
    fi
else
    # burst-guard
    if [[ ! -f "$LOGIND_DROPIN" ]]; then
        emit_status "drift" "missing $LOGIND_DROPIN"
        drift=$((drift + 1))
    elif ! head -1 "$LOGIND_DROPIN" | grep -qF "$HEADER_MARKER"; then
        emit_status "drift" "$LOGIND_DROPIN exists but lacks selfdef header marker"
        drift=$((drift + 1))
    elif ! grep -qE '^\s*CtrlAltDelBurstAction\s*=\s*none' "$LOGIND_DROPIN"; then
        emit_status "drift" "$LOGIND_DROPIN does not set CtrlAltDelBurstAction=none"
        drift=$((drift + 1))
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "ctrlaltdel-disable profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "ctrlaltdel-disable profile=$PROFILE no drift"
