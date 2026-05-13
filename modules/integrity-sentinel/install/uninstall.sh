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

# F-2027-024: walk the rendered-file manifest. apply.sh records
# the baseline path with module_record_file; we just iterate.
removed=0
manifest_count=0
while IFS= read -r dst; do
    [[ -z "$dst" ]] && continue
    manifest_count=$((manifest_count + 1))
    if [[ -f "$dst" ]]; then
        run "remove $dst" -- rm -f "$dst"
        removed=$((removed + 1))
    fi
done < <(module_render_files)

# Migration path: pre-v2 install OR uninstall-without-apply.
# Fall back to the legacy path resolution one last time so
# existing deployments don't leave the baseline orphaned.
if [[ "$manifest_count" -eq 0 ]]; then
    BASELINE_PATH="/var/lib/selfdef/integrity-sentinel/baseline.sha256"
    if [[ -r "$CONFIG_FILE" ]]; then
        BASELINE_PATH=$(toml_get baseline_path "$CONFIG_FILE" || echo "$BASELINE_PATH")
    fi
    if [[ -f "$BASELINE_PATH" ]]; then
        run "remove baseline $BASELINE_PATH (legacy enum)" -- rm -f "$BASELINE_PATH"
        removed=$((removed + 1))
    fi
fi

module_clear_manifest

emit_status "ok" "uninstalled (paths_file preserved, $removed file(s) removed)"
