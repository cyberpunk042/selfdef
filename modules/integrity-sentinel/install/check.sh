#!/usr/bin/env bash
# integrity-sentinel — check. No state changes.
#
# Same comparison as apply, but never creates or overwrites the
# baseline. A missing baseline is always reported as failed here
# (regardless of `on_missing`) because `check` is read-only and "no
# baseline yet" is a legitimate failure to surface to the operator.

set -euo pipefail

MODULE="integrity-sentinel"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_INTEGRITY_SENTINEL_CONFIG:-/etc/selfdef/modules/integrity-sentinel.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

command -v sha256sum >/dev/null || die "sha256sum(1) missing"
command -v diff      >/dev/null || die "diff(1) missing"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "strict")
PATHS_FILE=$(toml_get paths_file "$CONFIG_FILE" || echo "")
BASELINE_PATH=$(toml_get baseline_path "$CONFIG_FILE" || echo "")

[[ -n "$PATHS_FILE"    ]] || die "paths_file is required"
[[ -n "$BASELINE_PATH" ]] || die "baseline_path is required"
[[ -e "$BASELINE_PATH" ]] || die "no baseline at $BASELINE_PATH — run apply first"

TMP_CURRENT=$(mktemp)
trap 'rm -f "$TMP_CURRENT"' EXIT
expand_paths "$PATHS_FILE" | compute_baseline > "$TMP_CURRENT"
COUNT=$(wc -l < "$TMP_CURRENT" | tr -d ' ')

DIFF_OUT=$(diff -u "$BASELINE_PATH" "$TMP_CURRENT" || true)
if [[ -z "$DIFF_OUT" ]]; then
    emit_status "ok" "baseline matches ($COUNT entries)"
    exit 0
fi

ADDED=$(echo "$DIFF_OUT" | grep -c '^+[^+]' || true)
REMOVED=$(echo "$DIFF_OUT" | grep -c '^-[^-]' || true)
SUMMARY="DRIFT detected: +${ADDED} new/changed lines, -${REMOVED} missing/changed lines vs baseline"

log "$SUMMARY"
log "---- baseline diff ----"
log "$DIFF_OUT"
log "-----------------------"

# Same notifier wiring as apply.sh — gated on event_stream_path so a
# host with no daemon side stays silent.
emit_drift_event "$PROFILE" "$SUMMARY"

if [[ "$PROFILE" == "warn-only" ]]; then
    emit_status "ok" "$SUMMARY (warn-only: not blocking)"
    exit 0
fi
emit_status "failed" "$SUMMARY"
exit 1
