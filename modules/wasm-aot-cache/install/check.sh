#!/usr/bin/env bash
# wasm-aot-cache — check (SD-R48). Read-only.

set -euo pipefail

MODULE="wasm-aot-cache"
CACHE_DIR="${SELFDEF_WASM_AOT_CACHE_DIR:-/var/lib/selfdef/wasm-aot}"

emit_status() {
    local status="$1"
    local message="${2:-}"
    printf '{"module":"%s","status":"%s","message":"%s"}\n' \
        "${MODULE}" "${status}" "${message}"
}

missing=()
[ -d "${CACHE_DIR}" ]          || missing+=("${CACHE_DIR}")
[ -d "${CACHE_DIR}/cwasm" ]    || missing+=("${CACHE_DIR}/cwasm")
[ -d "${CACHE_DIR}/meta" ]     || missing+=("${CACHE_DIR}/meta")

if [ "${#missing[@]}" -eq 0 ]; then
    emit_status "ok" "cache dirs present"
    exit 0
fi
emit_status "failed" "missing: ${missing[*]}"
exit 1
