#!/usr/bin/env bash
# services-disable-printing — check. Read-only.

set -euo pipefail

MODULE="services-disable-printing"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_PRINTING_CONFIG:-/etc/selfdef/modules/services-disable-printing.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "mask")

drift=0
acted=0

if ! command -v systemctl >/dev/null 2>&1; then
    emit_status "ok" "services-disable-printing (systemctl unavailable)"
    exit 0
fi

for unit in "${PRINT_UNITS[@]}"; do
    if ! systemctl list-unit-files "$unit" >/dev/null 2>&1; then
        continue
    fi
    acted=$((acted + 1))

    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        emit_status "drift" "$unit is ACTIVE — should be stopped"
        drift=$((drift + 1))
    fi
    state=$(systemctl is-enabled "$unit" 2>/dev/null || echo "")
    if [[ "$PROFILE" == "mask" ]] && [[ "$state" != "masked" ]]; then
        emit_status "drift" "$unit is $state — mask profile requires masked"
        drift=$((drift + 1))
    fi
done

# Bonus: is cups still binding port 631 (IPP)?
if command -v ss >/dev/null 2>&1; then
    if ss -lntu 2>/dev/null | grep -q ':631 '; then
        emit_status "drift" "port 631 (IPP) STILL has a listener — cups may have been re-enabled"
        drift=$((drift + 1))
    fi
fi

if [[ "$acted" -eq 0 ]]; then
    log "no print/scan units installed on this host"
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "services-disable-printing profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "services-disable-printing profile=$PROFILE acted=$acted no drift"
