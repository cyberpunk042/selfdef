#!/usr/bin/env bash
# wasm-aot-cache — apply (SD-R48).
#
# Provisions /var/lib/selfdef/wasm-aot/ with subdirs for the canonical
# AOT compile pipeline:
#   .cwasm/      — pre-compiled artifacts
#   .meta/       — per-artifact JSON metadata
#   .last-tune   — symlink to /etc/selfdef/hardware-tune.env so
#                  consumers can detect tune-config drift via
#                  readlink + compare.
#
# Idempotent. SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="wasm-aot-cache"

emit_status() {
    local status="$1"
    local message="${2:-}"
    printf '{"module":"%s","status":"%s","message":"%s"}\n' \
        "${MODULE}" "${status}" "${message}"
}

CACHE_DIR="${SELFDEF_WASM_AOT_CACHE_DIR:-/var/lib/selfdef/wasm-aot}"
TUNE_FILE="${SELFDEF_HARDWARE_TUNE_ENV:-/etc/selfdef/hardware-tune.env}"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"

if [ "${DRY_RUN}" = "1" ]; then
    emit_status "skipped" "DRY-RUN — would provision ${CACHE_DIR}"
    exit 0
fi

mkdir -p "${CACHE_DIR}/cwasm" "${CACHE_DIR}/meta"
chmod 0755 "${CACHE_DIR}" "${CACHE_DIR}/cwasm" "${CACHE_DIR}/meta"

# Symlink to the hardware-tune env file (if present). Operators can
# `readlink ${CACHE_DIR}/.last-tune` to confirm which tune config the
# cache was provisioned against — if the symlink target's mtime is
# older than the actual env file, the cache is stale.
#
# Variant-A guard: only re-create the symlink when the target differs,
# otherwise `ln -sfn` re-creates the symlink every run + bumps the
# parent directory mtime, defeating idempotency.
if [ -f "${TUNE_FILE}" ]; then
    if [ ! -L "${CACHE_DIR}/.last-tune" ] || [ "$(readlink "${CACHE_DIR}/.last-tune")" != "${TUNE_FILE}" ]; then
        ln -sfn "${TUNE_FILE}" "${CACHE_DIR}/.last-tune"
    fi
fi

emit_status "ok" "provisioned ${CACHE_DIR}"
