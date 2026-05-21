#!/usr/bin/env bash
# chrony-baseline — uninstall.
#
# Removes /etc/chrony/conf.d/50-selfdef.conf + restarts chronyd
# so the OS-shipped /etc/chrony/chrony.conf is the only authority.
# Idempotent. SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="chrony-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
CHRONY_DROPIN_DIR="${SELFDEF_CHRONY_DROPIN_DIR:-/etc/chrony/conf.d}"
DST="${CHRONY_DROPIN_DIR}/50-selfdef.conf"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

removed=0
if [[ -f "$DST" ]]; then
    run "remove $(basename "$DST")" -- rm -f "$DST"
    removed=$((removed + 1))
fi

if [[ "$removed" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    run "restart chronyd" -- systemctl restart chronyd || \
        run "restart chrony" -- systemctl restart chrony || true
fi

emit_status "ok" "chrony-baseline removed=$removed"
