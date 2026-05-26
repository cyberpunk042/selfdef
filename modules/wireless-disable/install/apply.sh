#!/usr/bin/env bash
# wireless-disable — apply.

set -euo pipefail

MODULE="wireless-disable"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_WIRELESS_CONFIG:-/etc/selfdef/modules/wireless-disable.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "rfkill")
case "$PROFILE" in
    rfkill|mask) ;;
    *) die "profile must be rfkill|mask, got '$PROFILE'" ;;
esac

# Anti-lockout guard: if the ONLY network path is wireless,
# disabling Wi-Fi cuts the operator off. Detect a wired carrier;
# warn (don't hard-fail — operator may be on console).
have_wired=0
for n in /sys/class/net/*; do
    i=$(basename "$n")
    case "$i" in lo|wl*|wlan*|wwan*|ww*) continue ;; esac
    [[ -d "$n/wireless" ]] && continue
    if [[ -r "$n/carrier" ]] && [[ "$(cat "$n/carrier" 2>/dev/null)" == "1" ]]; then
        have_wired=1; break
    fi
done
if [[ "$have_wired" -eq 0 ]]; then
    log "WARN: no wired NIC with carrier detected — disabling Wi-Fi may cut remote access. Proceeding (assuming console/wired-pending); operator verify."
fi

# rfkill block (both profiles) — always safe + live.
if command -v rfkill >/dev/null 2>&1; then
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would rfkill block wifi"
    else
        run "rfkill block wifi" -- rfkill block wifi 2>/dev/null || true
    fi
fi

# mask profile: modprobe blacklist the Wi-Fi stack.
if [[ "$PROFILE" == "mask" ]]; then
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would write $MODPROBE_FILE"
    else
        tmp="$(mktemp "${MODPROBE_FILE}.XXXXXX")"
        {
            echo "$HEADER_MARKER"
            echo "# Generated $(date -u '+%Y-%m-%dT%H:%M:%SZ') — profile=mask"
            for m in "${WIFI_MODULES[@]}"; do
                echo "blacklist $m"
                echo "install $m /bin/true"
            done
        } > "$tmp"
        chmod 0644 "$tmp"
        mv -f "$tmp" "$MODPROBE_FILE"
        log "wrote $MODPROBE_FILE (${#WIFI_MODULES[@]} Wi-Fi modules blacklisted; effective next boot/reload)"
    fi
else
    # rfkill profile: ensure no stale mask file lingers.
    if [[ -f "$MODPROBE_FILE" ]] && head -1 "$MODPROBE_FILE" 2>/dev/null | grep -qF "$HEADER_MARKER"; then
        [[ "$DRY_RUN" == "1" ]] && log "DRY_RUN: would remove stale $MODPROBE_FILE" || { rm -f "$MODPROBE_FILE"; log "removed stale $MODPROBE_FILE (rfkill profile)"; }
    fi
fi

emit_status "ok" "wireless-disable profile=$PROFILE (wifi rfkill-blocked; wired_carrier=$have_wired)"
