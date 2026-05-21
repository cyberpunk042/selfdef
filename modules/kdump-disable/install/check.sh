#!/usr/bin/env bash
# kdump-disable — check. Read-only.

set -euo pipefail

MODULE="kdump-disable"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_KDUMP_DISABLE_CONFIG:-/etc/selfdef/modules/kdump-disable.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "mask")

drift=0
acted=0

if ! command -v systemctl >/dev/null 2>&1; then
    log "systemctl unavailable; check skipped"
    emit_status "ok" "kdump-disable (systemctl unavailable)"
    exit 0
fi

for unit in "${KDUMP_UNITS[@]}"; do
    if ! systemctl list-unit-files "$unit" >/dev/null 2>&1; then
        continue
    fi
    acted=$((acted + 1))

    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        emit_status "drift" "$unit is ACTIVE — should be stopped"
        drift=$((drift + 1))
    fi

    state=$(systemctl is-enabled "$unit" 2>/dev/null || echo "")
    if [[ "$PROFILE" == "mask" ]] && [[ "$state" != "masked" ]]; then
        emit_status "drift" "$unit is $state — mask profile requires masked"
        drift=$((drift + 1))
    fi
done

# Check /proc/cmdline for crashkernel= — operator may have an
# explicit kernel param reserving memory for kdump. We report
# but don't fail (operator-pull reboot needed to remove).
if [[ -r /proc/cmdline ]]; then
    if grep -qE 'crashkernel=' /proc/cmdline; then
        log "NOTE: /proc/cmdline contains crashkernel= — kernel reserved memory for kdump even though service is disabled. Remove from GRUB cmdline to fully reclaim."
    fi
fi

if [[ "$acted" -eq 0 ]]; then
    log "no kdump-related units present on this host"
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "kdump-disable profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "kdump-disable profile=$PROFILE no drift acted=$acted"
