#!/usr/bin/env bash
# ctrlaltdel-disable — apply.

set -euo pipefail

MODULE="ctrlaltdel-disable"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_CAD_CONFIG:-/etc/selfdef/modules/ctrlaltdel-disable.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
LOGIND_DROPIN_DIR="${SELFDEF_LOGIND_DROPIN_DIR:-/etc/systemd/logind.conf.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "mask")
case "$PROFILE" in
    mask|burst-guard) ;;
    *) die "profile must be mask|burst-guard, got '$PROFILE'" ;;
esac

if ! command -v systemctl >/dev/null 2>&1; then
    die "systemctl unavailable"
fi

if [[ "$PROFILE" == "mask" ]]; then
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would mask $CAD_TARGET"
    else
        run "mask $CAD_TARGET" -- systemctl mask "$CAD_TARGET" 2>/dev/null || true
    fi
    emit_status "ok" "ctrlaltdel-disable profile=mask ($CAD_TARGET masked)"
    exit 0
fi

# burst-guard: write logind drop-in disabling the burst
# immediate-reboot action (7 C-A-D presses in 2s).
mkdir -p "$LOGIND_DROPIN_DIR"
if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: would write $LOGIND_DROPIN with CtrlAltDelBurstAction=none"
    emit_status "ok" "ctrlaltdel-disable DRY_RUN profile=burst-guard"
    exit 0
fi

tmp="$(mktemp "${LOGIND_DROPIN}.XXXXXX")"
{
    echo "$HEADER_MARKER"
    echo "# Generated $(date -u '+%Y-%m-%dT%H:%M:%SZ') — profile=burst-guard"
    echo "[Login]"
    echo "CtrlAltDelBurstAction=none"
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$LOGIND_DROPIN"
log "wrote $LOGIND_DROPIN"

run "reload systemd-logind" -- systemctl kill -s HUP systemd-logind 2>/dev/null || true

emit_status "ok" "ctrlaltdel-disable profile=burst-guard (CtrlAltDelBurstAction=none)"
