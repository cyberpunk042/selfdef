#!/usr/bin/env bash
# usb-storage-mass-disable — apply.
#
# Installs /etc/modprobe.d/50-selfdef-usb-storage.conf with the
# chosen profile. Optionally unloads the module right now if it's
# currently loaded (so the block takes effect immediately).

set -euo pipefail

MODULE="usb-storage-mass-disable"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_USB_DISABLE_CONFIG:-/etc/selfdef/modules/usb-storage-mass-disable.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
CONFIGS_SRC="${MODULE_DIR}/configs"
MODPROBE_D="${SELFDEF_MODPROBE_D:-/etc/modprobe.d}"
DST="${MODPROBE_D}/50-selfdef-usb-storage.conf"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$CONFIGS_SRC" ]] || die "configs dir missing: $CONFIGS_SRC"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "blocked")
case "$PROFILE" in
    blocked|audited) ;;
    *) die "profile must be blocked|audited, got '$PROFILE'" ;;
esac

src="${CONFIGS_SRC}/${PROFILE}.conf"
[[ -r "$src" ]] || die "profile source missing: $src"

mkdir -p "$MODPROBE_D"

changes=0
if [[ -f "$DST" ]] && cmp -s "$src" "$DST"; then
    :
else
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would install $DST"
    else
        install -m 0644 "$src" "$DST"
    fi
    changes=$((changes + 1))
fi

# blocked profile: try to UNLOAD the modules right now (operator-
# pull defense doesn't wait for next boot).
if [[ "$PROFILE" == "blocked" ]] && [[ "$DRY_RUN" != "1" ]]; then
    for mod in usb_storage uas; do
        if lsmod | awk '{print $1}' | grep -qFx "$mod"; then
            if rmmod "$mod" 2>/dev/null; then
                log "rmmod $mod succeeded"
            else
                log "rmmod $mod failed (module in use); will block at NEXT load attempt"
            fi
        fi
    done
fi

emit_status "ok" "usb-storage-mass-disable profile=$PROFILE changes=$changes"
