#!/usr/bin/env bash
# tetragon — check. Read-only. No state changes.
#
# Verifies the substrate is healthy: config exists, policy_dir
# exists, event log path exists (or its parent does), and the
# systemd unit is active.

set -euo pipefail

MODULE="tetragon"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_TETRAGON_CONFIG:-/etc/selfdef/modules/tetragon.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

CONFIG_PATH=$(toml_get config_path  "$CONFIG_FILE" || echo "/etc/tetragon/tetragon.yaml")
POLICY_DIR=$(toml_get policy_dir    "$CONFIG_FILE" || echo "/etc/tetragon/tetragon.tp.d")
EVENT_LOG=$(toml_get event_log_path "$CONFIG_FILE" || echo "/var/log/tetragon/events.json")
SERVICE_UNIT=$(toml_get service_unit "$CONFIG_FILE" || echo "tetragon.service")

[[ -f "$CONFIG_PATH" ]]            || die "config not found at $CONFIG_PATH — run apply"
[[ -d "$POLICY_DIR" ]]             || die "policy dir not found: $POLICY_DIR"
[[ -d "$(dirname "$EVENT_LOG")" ]] || die "event log dir not found: $(dirname "$EVENT_LOG")"

if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet "$SERVICE_UNIT"; then
        die "$SERVICE_UNIT is not active"
    fi
fi

POLICY_COUNT=$(find "$POLICY_DIR" -maxdepth 1 -type f \( -name '*.yaml' -o -name '*.yml' \) 2>/dev/null | wc -l | tr -d ' ')
emit_status "ok" "tetragon substrate healthy ($POLICY_COUNT policy file(s) in $POLICY_DIR)"
