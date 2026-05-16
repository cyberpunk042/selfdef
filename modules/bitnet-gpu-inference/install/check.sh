#!/usr/bin/env bash
# bitnet-gpu-inference — check (SD-R28).
#
# Verifies the apply produced the expected artifacts. Read-only.

set -euo pipefail

MODULE="bitnet-gpu-inference"
ETC_DIR="${SELFDEF_BITNET_ETC_DIR:-/etc/selfdef/bitnet}"
STATE_DIR="${SELFDEF_BITNET_STATE_DIR:-/var/lib/selfdef/bitnet}"

emit_status() {
    local status="$1"
    local message="${2:-}"
    printf '{"module":"%s","status":"%s","message":"%s"}\n' \
        "${MODULE}" "${status}" "${message}"
}

missing=()
[ -d "${ETC_DIR}" ]                  || missing+=("${ETC_DIR}")
[ -d "${STATE_DIR}" ]                || missing+=("${STATE_DIR}")
[ -f "${ETC_DIR}/runtime.env" ]      || missing+=("${ETC_DIR}/runtime.env")
[ -f "${ETC_DIR}/schedule.json" ]    || missing+=("${ETC_DIR}/schedule.json")

if [ "${#missing[@]}" -eq 0 ]; then
    emit_status "ok" "all artifacts present"
    exit 0
fi

emit_status "failed" "missing: ${missing[*]}"
exit 1
