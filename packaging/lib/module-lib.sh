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

SELFDEF_MODULE_LIB_VERSION=2

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

# --- SDD-006 v2 helpers (added by F-2026-050 follow-up) -------
#
# Modules render zero or more files outside their own tree
# (TracingPolicies into /etc/tetragon/tetragon.tp.d/, systemd
# units into /etc/systemd/system/, etc). Pre-v2, uninstall.sh
# scripts had to hand-enumerate every expected output path —
# adding a new policy meant editing two scripts in lockstep,
# and forgetting one left orphan files behind.
#
# v2 adds a per-module install manifest: apply.sh calls
# `module_record_file <path>` for every file it writes;
# uninstall.sh iterates `module_render_files` to get the full
# list and removes each (then `module_clear_manifest` to wipe
# the record).
#
# The manifest lives at
#   ${MODULE_INSTALLED_MANIFEST:-/var/lib/selfdef/installed/<MODULE>.manifest}
# (one absolute path per line). Operators can also pre-stage
# this file to "tell selfdef this list of files is mine, please
# clean them up on uninstall" — useful for migrating an
# existing module to v2 without a fresh apply.

# Default manifest path for the current module. Override by
# exporting `MODULE_INSTALLED_MANIFEST` before sourcing this
# library (tests do).
selfdef_manifest_path() {
    if [[ -n "${MODULE_INSTALLED_MANIFEST:-}" ]]; then
        printf '%s' "${MODULE_INSTALLED_MANIFEST}"
    else
        printf '/var/lib/selfdef/installed/%s.manifest' "${MODULE}"
    fi
}

# Record one file path in the per-module install manifest. Dry-run
# aware: in DRY_RUN mode, logs the intent but does not touch the
# manifest. Idempotent: if the path is already recorded, doesn't
# duplicate.
module_record_file() {
    local path="$1"
    [[ -n "$path" ]] || return 0
    local manifest
    manifest=$(selfdef_manifest_path)
    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log "DRY-RUN: would record $path in $manifest"
        return 0
    fi
    local parent
    parent=$(dirname "$manifest")
    [[ -d "$parent" ]] || mkdir -p "$parent"
    # Dedup on append.
    if [[ -f "$manifest" ]] && grep -Fxq "$path" "$manifest"; then
        return 0
    fi
    printf '%s\n' "$path" >> "$manifest"
}

# Print every recorded path, one per line. Empty output when no
# manifest exists yet. Callers (uninstall.sh) iterate this and
# `rm -f` each entry.
module_render_files() {
    local manifest
    manifest=$(selfdef_manifest_path)
    [[ -f "$manifest" ]] || return 0
    cat "$manifest"
}

# Remove the per-module manifest. Called by uninstall.sh after
# removing every recorded file. Dry-run aware.
module_clear_manifest() {
    local manifest
    manifest=$(selfdef_manifest_path)
    [[ -f "$manifest" ]] || return 0
    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log "DRY-RUN: would clear manifest $manifest"
        return 0
    fi
    rm -f "$manifest"
}
