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

CONFIG_PATH="/etc/tetragon/tetragon.yaml"
POLICY_DIR="/etc/tetragon/tetragon.tp.d"
SERVICE_UNIT="tetragon.service"
if [[ -r "$CONFIG_FILE" ]]; then
    CONFIG_PATH=$(toml_get config_path  "$CONFIG_FILE" || echo "$CONFIG_PATH")
    POLICY_DIR=$(toml_get policy_dir    "$CONFIG_FILE" || echo "$POLICY_DIR")
    SERVICE_UNIT=$(toml_get service_unit "$CONFIG_FILE" || echo "$SERVICE_UNIT")
fi

if command -v systemctl >/dev/null 2>&1; then
    run "stop $SERVICE_UNIT" -- systemctl stop "$SERVICE_UNIT" || true
    run "disable $SERVICE_UNIT" -- systemctl disable "$SERVICE_UNIT" >/dev/null 2>&1 || true
fi

if [[ -f "$CONFIG_PATH" ]]; then
    run "remove $CONFIG_PATH" -- rm -f "$CONFIG_PATH"
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

emit_status "ok" "tetragon substrate removed"
