#!/usr/bin/env bash
# wwan-disable — apply.

set -euo pipefail

MODULE="wwan-disable"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_WWAN_CONFIG:-/etc/selfdef/modules/wwan-disable.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "rfkill")
case "$PROFILE" in
    rfkill|mask) ;;
    *) die "profile must be rfkill|mask, got '$PROFILE'" ;;
esac

# Anti-lockout guard: if the only network path is the modem,
# disabling it cuts the operator off. Detect a non-wwan carrier.
have_other=0
for n in /sys/class/net/*; do
    i=$(basename "$n")
    case "$i" in lo|ww*|wwan*) continue ;; esac
    if [[ -r "$n/carrier" ]] && [[ "$(cat "$n/carrier" 2>/dev/null)" == "1" ]]; then
        have_other=1; break
    fi
done
[[ "$have_other" -eq 0 ]] && log "WARN: no non-WWAN NIC with carrier — disabling the modem may cut remote access. Proceeding (assume console/wired-pending); operator verify."

# rfkill block wwan (both profiles) — always safe + live.
if command -v rfkill >/dev/null 2>&1; then
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would rfkill block wwan"
    else
        run "rfkill block wwan" -- rfkill block wwan 2>/dev/null || true
    fi
fi

# Stop + disable + mask ModemManager (both profiles).
if command -v systemctl >/dev/null 2>&1; then
    for unit in "${MM_UNITS[@]}"; do
        systemctl list-unit-files "$unit" >/dev/null 2>&1 || continue
        if [[ "$DRY_RUN" == "1" ]]; then
            log "DRY_RUN: would stop + disable + mask $unit"
        else
            run "stop $unit"    -- systemctl stop "$unit"    2>/dev/null || true
            run "disable $unit" -- systemctl disable "$unit" 2>/dev/null || true
            run "mask $unit"    -- systemctl mask "$unit"    2>/dev/null || true
        fi
    done
fi

# mask profile: modprobe blacklist the WWAN driver stack.
if [[ "$PROFILE" == "mask" ]]; then
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would write $MODPROBE_FILE"
    else
        tmp="$(mktemp "${MODPROBE_FILE}.XXXXXX")"
        {
            echo "$HEADER_MARKER"
            # No render-timestamp — defeats cmp -s idempotency (2026-06-06).
            echo "# profile=mask"
            for m in "${WWAN_MODULES[@]}"; do
                echo "blacklist $m"
                echo "install $m /bin/true"
            done
        } > "$tmp"
        chmod 0644 "$tmp"
        # Idempotency: skip rewrite when content unchanged.
        if [[ -f "$MODPROBE_FILE" ]] && cmp -s "$tmp" "$MODPROBE_FILE"; then
            rm -f "$tmp"
        else
            mv -f "$tmp" "$MODPROBE_FILE"
            log "wrote $MODPROBE_FILE (${#WWAN_MODULES[@]} WWAN modules blacklisted; effective next boot/reload)"
        fi
    fi
else
    # rfkill profile: drop any stale mask file.
    if [[ -f "$MODPROBE_FILE" ]] && head -1 "$MODPROBE_FILE" 2>/dev/null | grep -qF "$HEADER_MARKER"; then
        [[ "$DRY_RUN" == "1" ]] && log "DRY_RUN: would remove stale $MODPROBE_FILE" || { rm -f "$MODPROBE_FILE"; log "removed stale $MODPROBE_FILE (rfkill profile)"; }
    fi
fi

emit_status "ok" "wwan-disable profile=$PROFILE (wwan rfkill-blocked; ModemManager masked; other_carrier=$have_other)"
