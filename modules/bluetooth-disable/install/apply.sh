#!/usr/bin/env bash
# bluetooth-disable — apply.

set -euo pipefail

MODULE="bluetooth-disable"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_BLUETOOTH_CONFIG:-/etc/selfdef/modules/bluetooth-disable.toml}"
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

# 1. Stop + disable (+ mask) the user-space services.
acted=0
skipped=0
for unit in "${BT_UNITS[@]}"; do
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

# 2. rfkill block the radio (works even when bluez is uninstalled).
if command -v rfkill >/dev/null 2>&1; then
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would rfkill block bluetooth"
    else
        run "rfkill block bluetooth" -- rfkill block bluetooth 2>/dev/null || true
    fi
fi

# 3. Kernel-module blacklist (mask profile only).
if [[ "$PROFILE" == "mask" ]]; then
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would write $MODPROBE_BLACKLIST"
    else
        tmp="$(mktemp "${MODPROBE_BLACKLIST}.XXXXXX")"
        {
            echo "$HEADER_MARKER"
            echo "# Generated $(date -u '+%Y-%m-%dT%H:%M:%SZ') — do not edit."
            echo "# Blacklists bluetooth-related kernel modules so they"
            echo "# cannot be auto-loaded via uevent/coldplug after reboot."
            echo
            for m in "${BT_MODULES[@]}"; do
                echo "blacklist $m"
                echo "install $m /bin/true"
            done
        } > "$tmp"
        chmod 0644 "$tmp"
        mv -f "$tmp" "$MODPROBE_BLACKLIST"
        log "wrote $MODPROBE_BLACKLIST (blacklist + install-/bin/true for ${#BT_MODULES[@]} modules)"
    fi
fi

if [[ "$acted" -eq 0 && "$PROFILE" == "stop" ]]; then
    log "no bluetooth units present on this host — no-op"
fi

emit_status "ok" "bluetooth-disable profile=$PROFILE units_acted=$acted units_skipped=$skipped"
