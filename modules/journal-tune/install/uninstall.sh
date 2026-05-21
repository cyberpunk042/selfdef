#!/usr/bin/env bash
# journal-tune — uninstall.
#
# Removes only the selfdef drop-in. OS-shipped
# /etc/systemd/journald.conf + operator-extension drop-ins
# preserved byte-identical. Restarts systemd-journald so OS-default
# limits apply.

set -euo pipefail

MODULE="journal-tune"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
DROPIN_DIR="${SELFDEF_JOURNAL_DROPIN_DIR:-/etc/systemd/journald.conf.d}"
DST="${DROPIN_DIR}/50-selfdef.conf"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

removed=0
if [[ -f "$DST" ]]; then
    run "remove $(basename "$DST")" -- rm -f "$DST"
    removed=$((removed + 1))
fi

if [[ "$removed" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    run "systemctl restart systemd-journald" -- systemctl restart systemd-journald || true
fi

emit_status "ok" "journal-tune removed=$removed"
