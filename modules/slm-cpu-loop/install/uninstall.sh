#!/usr/bin/env bash
# slm-cpu-loop — uninstall (SD-R72).
#
# Removes the env file. PRESERVES operator-written systemd unit
# drop-ins (those live under /etc/systemd/system/<unit>.d/ and are
# operator-owned content).

set -euo pipefail

MODULE="slm-cpu-loop"
ENV_FILE="${SELFDEF_SLM_LOOP_ENV:-/etc/selfdef/slm-loop.env}"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"

emit_status() {
    local status="$1"
    local message="${2:-}"
    printf '{"module":"%s","status":"%s","message":"%s"}\n' \
        "${MODULE}" "${status}" "${message}"
}

if [ "${DRY_RUN}" = "1" ]; then
    emit_status "skipped" "DRY-RUN — would remove ${ENV_FILE}"
    exit 0
fi

rm -f "${ENV_FILE}"
emit_status "ok" "removed ${ENV_FILE}; preserved operator unit drop-ins"
