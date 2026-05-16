#!/usr/bin/env bash
# hardware-tune-cache — uninstall.
#
# Removes /etc/selfdef/hardware-tune.env. Honors SELFDEF_DRY_RUN=1.

set -euo pipefail

MODULE="hardware-tune-cache"

emit_status() {
    local status="$1"
    local message="${2:-}"
    printf '{"module":"%s","status":"%s","message":"%s"}\n' \
        "${MODULE}" "${status}" "${message}"
}

OUT_PATH="${SELFDEF_HARDWARE_TUNE_ENV:-/etc/selfdef/hardware-tune.env}"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"

if [ ! -f "${OUT_PATH}" ]; then
    emit_status "ok" "${OUT_PATH} not present; nothing to remove"
    exit 0
fi
if [ "${DRY_RUN}" = "1" ]; then
    emit_status "skipped" "DRY-RUN — would remove ${OUT_PATH}"
    exit 0
fi
rm -f "${OUT_PATH}"
emit_status "ok" "removed ${OUT_PATH}"
