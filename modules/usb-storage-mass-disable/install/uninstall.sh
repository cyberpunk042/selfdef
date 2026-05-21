#!/usr/bin/env bash
# usb-storage-mass-disable — uninstall.
#
# Removes the modprobe.d drop-in. usb_storage is now loadable on
# next hotplug event OR via explicit `modprobe usb_storage`.

set -euo pipefail

MODULE="usb-storage-mass-disable"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODPROBE_D="${SELFDEF_MODPROBE_D:-/etc/modprobe.d}"
DST="${MODPROBE_D}/50-selfdef-usb-storage.conf"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

removed=0
if [[ -f "$DST" ]]; then
    run "remove $(basename "$DST")" -- rm -f "$DST"
    removed=$((removed + 1))
fi

emit_status "ok" "usb-storage-mass-disable removed=$removed (NOTE: modules NOT auto-loaded by uninstall — next hotplug event OR `modprobe usb_storage` will trigger re-load)"
