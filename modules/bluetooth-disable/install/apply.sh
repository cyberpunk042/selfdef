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
            # No render-timestamp — defeats cmp -s idempotency (2026-06-06).
            echo "# Blacklists bluetooth-related kernel modules so they"
            echo "# cannot be auto-loaded via uevent/coldplug after reboot."
            echo
            for m in "${BT_MODULES[@]}"; do
                echo "blacklist $m"
                echo "install $m /bin/true"
            done
        } > "$tmp"
        chmod 0644 "$tmp"
        # Idempotency: skip rewrite when content unchanged.
        if [[ -f "$MODPROBE_BLACKLIST" ]] && cmp -s "$tmp" "$MODPROBE_BLACKLIST"; then
            rm -f "$tmp"
        else
            mv -f "$tmp" "$MODPROBE_BLACKLIST"
            log "wrote $MODPROBE_BLACKLIST (blacklist + install-/bin/true for ${#BT_MODULES[@]} modules)"
        fi
    fi
elif [[ "$PROFILE" == "stop" ]]; then
    # Profile downgrade mask → stop must remove the stale blacklist so the
    # operator's intent to relax (let BT come back after reboot) is honored.
    # Collateral-damage guard: only remove the file when the header marker
    # confirms it was written by us; an operator-authored blacklist with
    # the same path stays.
    if [[ -f "$MODPROBE_BLACKLIST" ]] && grep -q 'managed-by: selfdef bluetooth-disable' "$MODPROBE_BLACKLIST"; then
        if [[ "$DRY_RUN" == "1" ]]; then
            log "DRY_RUN: would remove stale $MODPROBE_BLACKLIST"
        else
            rm -f "$MODPROBE_BLACKLIST"
            log "removed stale $MODPROBE_BLACKLIST (profile downgrade mask → stop)"
        fi
    fi
fi

if [[ "$acted" -eq 0 && "$PROFILE" == "stop" ]]; then
    log "no bluetooth units present on this host — no-op"
fi

emit_status "ok" "bluetooth-disable profile=$PROFILE units_acted=$acted units_skipped=$skipped"
