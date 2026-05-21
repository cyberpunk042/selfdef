#!/usr/bin/env bash
# loopback-only-dns — uninstall.

set -euo pipefail

MODULE="loopback-only-dns"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
DROPIN_DIR="${SELFDEF_RESOLVED_DROPIN_DIR:-/etc/systemd/resolved.conf.d}"
DST="${DROPIN_DIR}/50-selfdef-loopback.conf"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

removed=0
if [[ -f "$DST" ]]; then
    run "remove $(basename "$DST")" -- rm -f "$DST"
    removed=$((removed + 1))
fi

if [[ "$removed" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    run "systemctl restart systemd-resolved" -- systemctl restart systemd-resolved || true
fi

emit_status "ok" "loopback-only-dns removed=$removed"
