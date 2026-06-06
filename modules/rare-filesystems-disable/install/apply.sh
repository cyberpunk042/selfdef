#!/usr/bin/env bash
# rare-filesystems-disable — apply.

set -euo pipefail

MODULE="rare-filesystems-disable"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_RAREFS_CONFIG:-/etc/selfdef/modules/rare-filesystems-disable.toml}"
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
    emit_status "ok" "rare-filesystems-disable DRY_RUN profile=$PROFILE"
    exit 0
fi

tmp="$(mktemp "${MODPROBE_FILE}.XXXXXX")"
{
    echo "$HEADER_MARKER"
    # No render-timestamp — defeats cmp -s idempotency (2026-06-06).
    echo "# profile=$PROFILE"
    cat "$SRC"
} > "$tmp"
chmod 0644 "$tmp"

# Idempotency: skip rewrite when content unchanged.
if [[ -f "$MODPROBE_FILE" ]] && cmp -s "$tmp" "$MODPROBE_FILE"; then
    rm -f "$tmp"
else
    mv -f "$tmp" "$MODPROBE_FILE"
    log "wrote $MODPROBE_FILE"
fi

# Warn if any of the target modules is currently loaded (the
# blacklist takes effect on NEXT load; current load persists
# until rmmod or reboot).
if [[ -r /proc/modules ]]; then
    case "$PROFILE" in
        baseline) mods=("${BASELINE_MODS[@]}") ;;
        strict)   mods=("${STRICT_MODS[@]}") ;;
    esac
    for m in "${mods[@]}"; do
        if awk -v m="$m" '$1 == m { found=1 } END { exit !found }' /proc/modules; then
            log "WARN: kernel module '$m' is loaded; blacklist takes effect on next reboot/rmmod"
        fi
    done
fi

emit_status "ok" "rare-filesystems-disable profile=$PROFILE"
