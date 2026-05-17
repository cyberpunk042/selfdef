#!/usr/bin/env bash
# tensor-parallel-inference — check (SD-R58). Read-only.

set -euo pipefail

MODULE="tensor-parallel-inference"
ETC_DIR="${SELFDEF_TENSOR_PARALLEL_ETC_DIR:-/etc/selfdef/tensor-parallel}"

emit_status() {
    local status="$1"
    local message="${2:-}"
    printf '{"module":"%s","status":"%s","message":"%s"}\n' \
        "${MODULE}" "${status}" "${message}"
}

missing=()
[ -d "${ETC_DIR}" ]                  || missing+=("${ETC_DIR}")
[ -f "${ETC_DIR}/slice-plan.json" ]  || missing+=("${ETC_DIR}/slice-plan.json")
[ -f "${ETC_DIR}/runtime.env" ]      || missing+=("${ETC_DIR}/runtime.env")

if [ "${#missing[@]}" -eq 0 ]; then
    emit_status "ok" "tensor-parallel artifacts present"
    exit 0
fi
emit_status "failed" "missing: ${missing[*]}"
exit 1
