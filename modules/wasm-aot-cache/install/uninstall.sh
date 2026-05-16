#!/usr/bin/env bash
# wasm-aot-cache — uninstall (SD-R48).
#
# Removes the .last-tune symlink + the meta dir (cleared on
# uninstall). PRESERVES the .cwasm artifacts dir — operators may
# want to keep their AOT cache across module re-applies (rebuilding
# is expensive on large pipelines).

set -euo pipefail

MODULE="wasm-aot-cache"
CACHE_DIR="${SELFDEF_WASM_AOT_CACHE_DIR:-/var/lib/selfdef/wasm-aot}"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"

emit_status() {
    local status="$1"
    local message="${2:-}"
    printf '{"module":"%s","status":"%s","message":"%s"}\n' \
        "${MODULE}" "${status}" "${message}"
}

if [ "${DRY_RUN}" = "1" ]; then
    emit_status "skipped" "DRY-RUN — would remove ${CACHE_DIR}/.last-tune + meta"
    exit 0
fi

rm -f "${CACHE_DIR}/.last-tune"
rm -rf "${CACHE_DIR}/meta"

emit_status "ok" "removed .last-tune + meta; preserved cwasm/"
