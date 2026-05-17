#!/usr/bin/env bash
# slm-cpu-loop — check (SD-R72). Read-only.

set -euo pipefail

MODULE="slm-cpu-loop"
ENV_FILE="${SELFDEF_SLM_LOOP_ENV:-/etc/selfdef/slm-loop.env}"

emit_status() {
    local status="$1"
    local message="${2:-}"
    printf '{"module":"%s","status":"%s","message":"%s"}\n' \
        "${MODULE}" "${status}" "${message}"
}

if [ ! -f "${ENV_FILE}" ]; then
    emit_status "failed" "${ENV_FILE} missing — run apply first"
    exit 1
fi

# The env file should have the canonical knobs even when the
# operator hasn't yet set SELFDEF_SLM_MODEL.
for key in SELFDEF_SLM_AFFINITY SELFDEF_SLM_THREADS SELFDEF_SLM_ENGINE; do
    if ! grep -q "^${key}=" "${ENV_FILE}"; then
        emit_status "failed" "env file missing ${key}"
        exit 1
    fi
done

emit_status "ok" "env file present + carries SLM loop defaults"
