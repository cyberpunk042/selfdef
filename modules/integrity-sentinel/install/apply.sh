#!/usr/bin/env bash
# integrity-sentinel — apply.
#
# On first run (no baseline exists) and `on_missing = "create"`:
#   - Compute SHA256 of every path resolved from paths_file.
#   - Write the baseline to baseline_path in sha256sum format.
#   - Status: ok.
#
# On subsequent runs:
#   - Recompute SHA256 over the same expansion.
#   - Diff against the stored baseline.
#   - If clean: status ok.
#   - If drift: status failed (strict) or status ok-with-DRIFT (warn-only).

set -euo pipefail

MODULE="integrity-sentinel"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
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
ON_MISSING=$(toml_get on_missing "$CONFIG_FILE" || echo "create")

case "$PROFILE" in
    strict|warn-only) ;;
    *) die "profile must be strict|warn-only, got '$PROFILE'" ;;
esac
case "$ON_MISSING" in
    create|fail) ;;
    *) die "on_missing must be create|fail, got '$ON_MISSING'" ;;
esac
[[ -n "$PATHS_FILE"    ]] || die "paths_file is required"
[[ -n "$BASELINE_PATH" ]] || die "baseline_path is required"

# Always recompute the "current" baseline view; that's the same work
# regardless of whether we're creating or verifying.
TMP_CURRENT=$(mktemp)
trap 'rm -f "$TMP_CURRENT"' EXIT
expand_paths "$PATHS_FILE" | compute_baseline > "$TMP_CURRENT"
COUNT=$(wc -l < "$TMP_CURRENT" | tr -d ' ')

if [[ ! -e "$BASELINE_PATH" ]]; then
    if [[ "$ON_MISSING" == "fail" ]]; then
        die "no baseline at $BASELINE_PATH and on_missing=fail"
    fi
    # First run: write the baseline.
    BASELINE_DIR=$(dirname "$BASELINE_PATH")
    if [[ ! -d "$BASELINE_DIR" ]]; then
        run "create baseline dir $BASELINE_DIR" -- mkdir -p "$BASELINE_DIR"
    fi
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY-RUN: would write $COUNT entries to $BASELINE_PATH"
    else
        install -m 0600 /dev/null "$BASELINE_PATH"
        cp "$TMP_CURRENT" "$BASELINE_PATH"
        chmod 0600 "$BASELINE_PATH"
    fi
    emit_status "ok" "baseline created ($COUNT entries) at $BASELINE_PATH"
    exit 0
fi

# Baseline exists — verify.
DIFF_OUT=$(diff -u "$BASELINE_PATH" "$TMP_CURRENT" || true)
if [[ -z "$DIFF_OUT" ]]; then
    emit_status "ok" "baseline matches ($COUNT entries)"
    exit 0
fi

# Drift detected. Summarise: count added / removed / changed.
ADDED=$(echo "$DIFF_OUT" | grep -c '^+[^+]' || true)
REMOVED=$(echo "$DIFF_OUT" | grep -c '^-[^-]' || true)
SUMMARY="DRIFT detected: +${ADDED} new/changed lines, -${REMOVED} missing/changed lines vs baseline"

# Always log the full diff to stderr — operators want it for triage.
log "$SUMMARY"
log "---- baseline diff ----"
log "$DIFF_OUT"
log "-----------------------"

# Notify the daemon (if it's listening on an eventstream path).
# Gated entirely on `event_stream_path` being set in the host config,
# so deployments without a daemon stay quiet.
emit_drift_event "$PROFILE" "$SUMMARY"

if [[ "$PROFILE" == "strict" ]]; then
    emit_status "failed" "$SUMMARY"
    exit 1
fi

# warn-only: still report ok so a `selfdefctl modules apply` continues,
# but tag the message clearly so the operator notices.
emit_status "ok" "$SUMMARY (warn-only: not blocking)"
