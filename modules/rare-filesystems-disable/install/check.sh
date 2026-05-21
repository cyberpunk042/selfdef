#!/usr/bin/env bash
# rare-filesystems-disable — check. Read-only.

set -euo pipefail

MODULE="rare-filesystems-disable"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_RAREFS_CONFIG:-/etc/selfdef/modules/rare-filesystems-disable.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "baseline")

drift=0
if [[ ! -f "$MODPROBE_FILE" ]]; then
    emit_status "drift" "missing $MODPROBE_FILE"
    drift=$((drift + 1))
elif ! head -1 "$MODPROBE_FILE" | grep -qF "$HEADER_MARKER"; then
    emit_status "drift" "$MODPROBE_FILE exists but lacks selfdef header marker"
    drift=$((drift + 1))
fi

# Check if any blacklisted module is currently loaded.
if [[ -r /proc/modules ]]; then
    case "$PROFILE" in
        baseline) mods=("${BASELINE_MODS[@]}") ;;
        strict)   mods=("${STRICT_MODS[@]}") ;;
    esac
    for m in "${mods[@]}"; do
        if awk -v m="$m" '$1 == m { found=1 } END { exit !found }' /proc/modules; then
            emit_status "drift" "kernel module '$m' is loaded (blacklist takes effect next reboot)"
            drift=$((drift + 1))
        fi
    done
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "rare-filesystems-disable profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "rare-filesystems-disable profile=$PROFILE no drift"
