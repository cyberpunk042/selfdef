#!/usr/bin/env bash
# bitnet-gpu-inference — uninstall (SD-R28).
#
# Removes the runtime.env + schedule.json. Leaves the state dir
# (/var/lib/selfdef/bitnet/) intact — that's where session caches +
# loaded model fingerprints live, and operators may want to keep
# them across re-applies.

set -euo pipefail

MODULE="bitnet-gpu-inference"
ETC_DIR="${SELFDEF_BITNET_ETC_DIR:-/etc/selfdef/bitnet}"

emit_status() {
    local status="$1"
    local message="${2:-}"
    printf '{"module":"%s","status":"%s","message":"%s"}\n' \
        "${MODULE}" "${status}" "${message}"
}

DRY_RUN="${SELFDEF_DRY_RUN:-0}"
if [ "${DRY_RUN}" = "1" ]; then
    emit_status "skipped" "DRY-RUN — would remove ${ETC_DIR}"
    exit 0
fi

rm -f "${ETC_DIR}/runtime.env" "${ETC_DIR}/schedule.json"
# Prune empty dir but ignore "not empty" — operator may have other
# bitnet-* modules sharing the dir.
rmdir "${ETC_DIR}" 2>/dev/null || true

emit_status "ok" "removed runtime.env + schedule.json from ${ETC_DIR}"
