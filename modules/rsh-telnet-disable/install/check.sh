#!/usr/bin/env bash
# rsh-telnet-disable — check. Read-only.

set -euo pipefail

MODULE="rsh-telnet-disable"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_LEGACY_CONFIG:-/etc/selfdef/modules/rsh-telnet-disable.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "mask")

drift=0
acted=0

if ! command -v systemctl >/dev/null 2>&1; then
    emit_status "ok" "rsh-telnet-disable (systemctl unavailable)"
    exit 0
fi

for unit in "${LEGACY_UNITS[@]}"; do
    if ! systemctl list-unit-files "$unit" >/dev/null 2>&1; then
        continue
    fi
    acted=$((acted + 1))
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        emit_status "drift" "$unit is ACTIVE — cleartext protocol should be stopped"
        drift=$((drift + 1))
    fi
    state=$(systemctl is-enabled "$unit" 2>/dev/null || echo "")
    if [[ "$PROFILE" == "mask" ]] && [[ "$state" != "masked" ]]; then
        emit_status "drift" "$unit is $state — mask profile requires masked"
        drift=$((drift + 1))
    fi
done

# Bonus: anything bound to the classic cleartext ports?
if command -v ss >/dev/null 2>&1; then
    for portspec in ':23 ' ':513 ' ':514 ' ':512 ' ':69 ' ':79 '; do
        if ss -lntu 2>/dev/null | grep -q "$portspec"; then
            emit_status "drift" "a legacy port (${portspec// /}) STILL has a listener"
            drift=$((drift + 1))
        fi
    done
fi

if [[ "$acted" -eq 0 ]]; then
    log "no legacy cleartext units installed (healthy)"
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "rsh-telnet-disable profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "rsh-telnet-disable profile=$PROFILE acted=$acted no drift"
