#!/usr/bin/env bash
# usb-storage-mass-disable — check. Read-only.

set -euo pipefail

MODULE="usb-storage-mass-disable"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_USB_DISABLE_CONFIG:-/etc/selfdef/modules/usb-storage-mass-disable.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODPROBE_D="${SELFDEF_MODPROBE_D:-/etc/modprobe.d}"
DST="${MODPROBE_D}/50-selfdef-usb-storage.conf"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "blocked")

drift=0
[[ -f "$DST" ]] || { emit_status "drift" "modprobe drop-in missing: $DST"; drift=$((drift + 1)); }

# Live check: usb_storage should NOT be loaded under blocked profile.
if [[ "$PROFILE" == "blocked" ]]; then
    if lsmod 2>/dev/null | awk '{print $1}' | grep -qFx usb_storage; then
        emit_status "drift" "usb_storage is currently LOADED (blocked profile expects unloaded) — rmmod failed at apply OR module re-loaded since"
        drift=$((drift + 1))
    fi
fi

# Verify the install-override is effective by attempting to load
# the module (modprobe consults install-override + runs the
# fake install command instead of loading).
if command -v modprobe >/dev/null 2>&1; then
    # modprobe --show-depends prints the install command path
    # without executing it.
    if depends=$(modprobe --show-depends usb_storage 2>&1); then
        if echo "$depends" | grep -qE 'install /bin/true|install /bin/sh'; then
            log "modprobe --show-depends usb_storage shows install-override (drop-in effective)"
        else
            emit_status "drift" "modprobe --show-depends usb_storage does NOT show install-override — drop-in not picked up by modprobe"
            drift=$((drift + 1))
        fi
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "usb-storage-mass-disable profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "usb-storage-mass-disable profile=$PROFILE no drift"
