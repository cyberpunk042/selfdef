#!/usr/bin/env bash
# coredumpd-redirect — uninstall.
#
# Removes the systemd-coredump drop-in. Does NOT delete the
# /var/lib/selfdef/coredumps/ directory — it may contain
# operator-preserved forensic data the operator wants to retain.
# Operator must `rm -rf` it manually if they want to reclaim the
# space.
#
# Restarts systemd-coredump.socket so subsequent crashes use the
# OS-default storage location (typically /var/lib/systemd/coredump/).
# Idempotent. SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="coredumpd-redirect"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
DROPIN_DIR="${SELFDEF_COREDUMPD_DROPIN_DIR:-/etc/systemd/coredump.conf.d}"
DST="${DROPIN_DIR}/50-selfdef.conf"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

removed=0
if [[ -f "$DST" ]]; then
    run "remove $(basename "$DST")" -- rm -f "$DST"
    removed=$((removed + 1))
fi

if [[ "$removed" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    run "systemctl daemon-reload" -- systemctl daemon-reload || true
    run "restart systemd-coredump.socket" -- systemctl restart systemd-coredump.socket || true
fi

emit_status "ok" "coredumpd-redirect removed=$removed (NOTE: /var/lib/selfdef/coredumps/ preserved — rm manually to reclaim)"
