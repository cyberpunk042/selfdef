#!/usr/bin/env bash
# rare-network-protocols-disable — apply.

set -euo pipefail

MODULE="rare-network-protocols-disable"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_RARENET_CONFIG:-/etc/selfdef/modules/rare-network-protocols-disable.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "baseline")
case "$PROFILE" in
    baseline|strict) ;;
    *) die "profile must be baseline|strict, got '$PROFILE'" ;;
esac

SRC="${LIB_DIR}/../configs/${PROFILE}.conf"
[[ -r "$SRC" ]] || die "missing config source: $SRC"

if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: would render $MODPROBE_FILE from $SRC"
    emit_status "ok" "rare-network-protocols-disable DRY_RUN profile=$PROFILE"
    exit 0
fi

tmp="$(mktemp "${MODPROBE_FILE}.XXXXXX")"
{
    echo "$HEADER_MARKER"
    echo "# Generated $(date -u '+%Y-%m-%dT%H:%M:%SZ') — profile=$PROFILE"
    cat "$SRC"
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$MODPROBE_FILE"
log "wrote $MODPROBE_FILE"

if [[ -r /proc/modules ]]; then
    case "$PROFILE" in
        baseline) mods=("${BASELINE_MODS[@]}") ;;
        strict)   mods=("${STRICT_MODS[@]}") ;;
    esac
    for m in "${mods[@]}"; do
        if awk -v m="$m" '$1 == m { found=1 } END { exit !found }' /proc/modules; then
            log "WARN: kernel module '$m' is loaded; blacklist takes effect next reboot/rmmod"
        fi
    done
fi

emit_status "ok" "rare-network-protocols-disable profile=$PROFILE"
