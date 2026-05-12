#!/usr/bin/env bash
# integrity-sentinel — uninstall.
#
# Removes the recorded baseline so a fresh `apply` can re-seal. Does
# NOT touch the paths_file — the operator owns that.

set -euo pipefail

MODULE="integrity-sentinel"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_INTEGRITY_SENTINEL_CONFIG:-/etc/selfdef/modules/integrity-sentinel.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

# Best-effort: even if the config is gone, try the default baseline
# path so an operator who's already deleted /etc/selfdef/... can still
# clean up /var/lib state.
BASELINE_PATH="/var/lib/selfdef/integrity-sentinel/baseline.sha256"
if [[ -r "$CONFIG_FILE" ]]; then
    BASELINE_PATH=$(toml_get baseline_path "$CONFIG_FILE" || echo "$BASELINE_PATH")
fi

if [[ -f "$BASELINE_PATH" ]]; then
    run "remove baseline $BASELINE_PATH" -- rm -f "$BASELINE_PATH"
fi
emit_status "ok" "uninstalled (paths_file preserved)"
