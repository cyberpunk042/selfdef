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
REQUIRE_SIGNED=$(toml_get require_signed_policies "$CONFIG_FILE" || echo "false")

[[ -f "$CONFIG_PATH" ]]            || die "config not found at $CONFIG_PATH — run apply"
[[ -d "$POLICY_DIR" ]]             || die "policy dir not found: $POLICY_DIR"
[[ -d "$(dirname "$EVENT_LOG")" ]] || die "event log dir not found: $(dirname "$EVENT_LOG")"

if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet "$SERVICE_UNIT"; then
        die "$SERVICE_UNIT is not active"
    fi
fi

POLICY_COUNT=$(find "$POLICY_DIR" -maxdepth 1 -type f \( -name '*.yaml' -o -name '*.yml' \) 2>/dev/null | wc -l | tr -d ' ')

# SDD-004 F-2026-024 follow-up: surface unsigned-policy count when
# verification is opted in. Non-fatal in check.sh — apply.sh
# already gates the live restart on this; check.sh's job is to
# report state, so an unsigned policy in a running deployment
# becomes a `failed` status the operator can investigate.
if [[ "$REQUIRE_SIGNED" == "true" ]]; then
    if ! command -v selfdefctl >/dev/null; then
        die "require_signed_policies=true but selfdefctl is not on PATH"
    fi
    unsigned=0
    # shellcheck disable=SC2044
    for p in $(find "$POLICY_DIR" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null); do
        if ! selfdefctl keys verify "$p" >/dev/null 2>&1; then
            unsigned=$((unsigned + 1))
        fi
    done
    if [[ "$unsigned" -gt 0 ]]; then
        emit_status "failed" "$unsigned of $POLICY_COUNT policy file(s) in $POLICY_DIR failed signature verification"
        exit 1
    fi
fi

emit_status "ok" "tetragon substrate healthy ($POLICY_COUNT policy file(s) in $POLICY_DIR)"
