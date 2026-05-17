#!/usr/bin/env bash
# tensor-parallel-inference — uninstall (SD-R58).

set -euo pipefail

MODULE="tensor-parallel-inference"
ETC_DIR="${SELFDEF_TENSOR_PARALLEL_ETC_DIR:-/etc/selfdef/tensor-parallel}"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"

emit_status() {
    local status="$1"
    local message="${2:-}"
    printf '{"module":"%s","status":"%s","message":"%s"}\n' \
        "${MODULE}" "${status}" "${message}"
}

if [ "${DRY_RUN}" = "1" ]; then
    emit_status "skipped" "DRY-RUN — would remove ${ETC_DIR}"
    exit 0
fi

rm -f "${ETC_DIR}/slice-plan.json" "${ETC_DIR}/runtime.env"
rmdir "${ETC_DIR}" 2>/dev/null || true

emit_status "ok" "removed ${ETC_DIR}"
