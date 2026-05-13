#!/usr/bin/env bash
# tetragon — uninstall.
#
# Stops Tetragon, removes the rendered config + the event log dir
# and the policy directory if it's empty. We deliberately do NOT
# remove the Tetragon binary (operator installed it; operator owns
# it) or non-empty policy_dirs (a policy module may still be
# active).
#
# Idempotent. SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="tetragon"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_TETRAGON_CONFIG:-/etc/selfdef/modules/tetragon.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

POLICY_DIR="/etc/tetragon/tetragon.tp.d"
SERVICE_UNIT="tetragon.service"
if [[ -r "$CONFIG_FILE" ]]; then
    POLICY_DIR=$(toml_get policy_dir    "$CONFIG_FILE" || echo "$POLICY_DIR")
    SERVICE_UNIT=$(toml_get service_unit "$CONFIG_FILE" || echo "$SERVICE_UNIT")
fi

if command -v systemctl >/dev/null 2>&1; then
    run "stop $SERVICE_UNIT" -- systemctl stop "$SERVICE_UNIT" || true
    run "disable $SERVICE_UNIT" -- systemctl disable "$SERVICE_UNIT" >/dev/null 2>&1 || true
fi

# F-2027-024: walk the rendered-file manifest. apply.sh records
# CONFIG_PATH; we just iterate. policy_dir + event_log are NOT
# in the manifest by design — they're operator-owned drop dirs
# that long outlive this module's installation.
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

# Migration path: pre-v2 install. Re-derive CONFIG_PATH the
# same way apply.sh does and remove it.
if [[ "$manifest_count" -eq 0 ]]; then
    LEGACY_CONFIG_PATH="/etc/tetragon/tetragon.yaml"
    if [[ -r "$CONFIG_FILE" ]]; then
        LEGACY_CONFIG_PATH=$(toml_get config_path "$CONFIG_FILE" || echo "$LEGACY_CONFIG_PATH")
    fi
    if [[ -f "$LEGACY_CONFIG_PATH" ]]; then
        run "remove $LEGACY_CONFIG_PATH (legacy enum)" -- rm -f "$LEGACY_CONFIG_PATH"
        removed=$((removed + 1))
    fi
fi

# Only remove the policy_dir if empty — refuse to take a live policy
# bundle out from under another module.
if [[ -d "$POLICY_DIR" ]]; then
    if [[ -z "$(ls -A "$POLICY_DIR" 2>/dev/null)" ]]; then
        run "remove empty $POLICY_DIR" -- rmdir "$POLICY_DIR"
    else
        log "leaving $POLICY_DIR alone — still contains policy files (uninstall those modules first)"
    fi
fi

module_clear_manifest

emit_status "ok" "tetragon substrate removed ($removed file(s))"
