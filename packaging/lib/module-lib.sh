# shellcheck shell=bash
# selfdef shared module-script library (SDD-006).
#
# Sourced by every module's apply.sh / check.sh / uninstall.sh
# after MODULE and DRY_RUN have been set. Provides the five
# helpers that used to live (byte-identical) in each module's
# install/lib.sh: log, emit_status, die, run, toml_get.
#
# Caller contract (must be set before sourcing):
#   MODULE       — module slug, e.g. "tetragon". Used by log()
#                  and emit_status() to identify the module in
#                  stderr lines and the final structured-status
#                  JSON object.
#   DRY_RUN      — "0" or "1". When "1", run() logs the command
#                  it would have executed and skips it.
#
# Caller may set (optional):
#   SELFDEF_MODULE_LIB_VERSION_REQUIRED — minimum library
#       version the module needs. If unset, defaults to 1.
#       Modules that depend on a helper added in a later
#       version bump set this; older selfdef installs without
#       the helper exit 99 at source time with a clear message.
#
# Installation path: /usr/share/selfdef/lib/module-lib.sh
# (set by the .deb assets list). In a workspace, selfdefctl
# exports SELFDEF_MODULE_LIB pointing at this file under the
# source tree.

SELFDEF_MODULE_LIB_VERSION=1

if [[ "${SELFDEF_MODULE_LIB_VERSION_REQUIRED:-1}" -gt \
      "${SELFDEF_MODULE_LIB_VERSION}" ]]; then
    echo "[${MODULE:-?}] shared module-lib version mismatch: \
require >=${SELFDEF_MODULE_LIB_VERSION_REQUIRED}, have \
${SELFDEF_MODULE_LIB_VERSION}" >&2
    exit 99
fi

log() { echo "[${MODULE}] $*" >&2; }

emit_status() {
    local status="$1" message="$2"
    printf '{"module":"%s","status":"%s","message":"%s"}\n' \
        "$MODULE" "$status" "${message//\"/\\\"}"
}

die() { emit_status "failed" "$*"; exit 1; }

run() {
    local desc="$1"; shift
    [[ "$1" == "--" ]] && shift
    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log "DRY-RUN: $desc"
        log "    \$ $*"
    else
        log "$desc"
        "$@"
    fi
}

toml_get() {
    local key="$1" file="$2"
    local line
    line=$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$file" | head -1 || true)
    [[ -z "$line" ]] && return 1
    line="${line#*=}"; line="${line## }"; line="${line%% #*}"
    line="${line%\"}"; line="${line#\"}"
    printf '%s' "$line"
}
