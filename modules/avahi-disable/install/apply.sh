#!/usr/bin/env bash
# avahi-disable — apply.

set -euo pipefail

MODULE="avahi-disable"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_AVAHI_CONFIG:-/etc/selfdef/modules/avahi-disable.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "mask")
case "$PROFILE" in
    mask|stop) ;;
    *) die "profile must be mask|stop, got '$PROFILE'" ;;
esac

if ! command -v systemctl >/dev/null 2>&1; then
    die "systemctl unavailable"
fi

acted=0
skipped=0
for unit in "${AVAHI_UNITS[@]}"; do
    if ! systemctl list-unit-files "$unit" >/dev/null 2>&1; then
        skipped=$((skipped + 1))
        continue
    fi
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would stop + disable $unit"
        [[ "$PROFILE" == "mask" ]] && log "DRY_RUN: would mask $unit"
        acted=$((acted + 1))
        continue
    fi
    run "stop $unit"    -- systemctl stop "$unit"    2>/dev/null || true
    run "disable $unit" -- systemctl disable "$unit" 2>/dev/null || true
    if [[ "$PROFILE" == "mask" ]]; then
        run "mask $unit" -- systemctl mask "$unit" 2>/dev/null || true
    fi
    acted=$((acted + 1))
done

if [[ "$acted" -eq 0 ]]; then
    log "avahi not installed on this host — no-op"
    emit_status "ok" "avahi-disable no-op (avahi not present)"
    exit 0
fi

emit_status "ok" "avahi-disable profile=$PROFILE acted=$acted skipped=$skipped"
