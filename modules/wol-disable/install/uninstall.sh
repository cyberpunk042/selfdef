#!/usr/bin/env bash
# wol-disable — uninstall.
#
# Disables + removes the service unit + script. Does NOT
# re-enable WoL on NICs (operator decides via `ethtool -s
# <iface> wol g` if they want WoL back).

set -euo pipefail

MODULE="wol-disable"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if command -v systemctl >/dev/null 2>&1 && [[ "$DRY_RUN" != "1" ]]; then
    systemctl disable selfdef-wol-disable.service 2>/dev/null || true
    systemctl reset-failed selfdef-wol-disable.service 2>/dev/null || true
fi

removed=0
for f in "${SYSTEMD_DIR}/selfdef-wol-disable.service" \
         "${LIBEXEC_DIR}/wol-disable.sh"; do
    if [[ -f "$f" ]]; then
        run "remove $(basename "$f")" -- rm -f "$f"
        removed=$((removed + 1))
    fi
done

DROPIN_DIR_SVC="${SYSTEMD_DIR}/selfdef-wol-disable.service.d"
if [[ -d "$DROPIN_DIR_SVC" ]]; then
    run "rm -r ${DROPIN_DIR_SVC}" -- rm -rf "$DROPIN_DIR_SVC"
    removed=$((removed + 1))
fi

if [[ "$removed" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    run "systemctl daemon-reload" -- systemctl daemon-reload || true
fi

emit_status "ok" "wol-disable removed=$removed (NOTE: WoL on NICs NOT re-enabled; operator runs ethtool -s <iface> wol g to re-enable)"
