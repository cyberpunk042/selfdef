#!/usr/bin/env bash
# tetragon — apply.
#
# Renders /etc/tetragon/tetragon.yaml, ensures policy_dir exists,
# enables the systemd unit, restarts only when the config actually
# changed. Idempotent. SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="tetragon"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_TETRAGON_CONFIG:-/etc/selfdef/modules/tetragon.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
command -v tetragon  >/dev/null || die "tetragon(1) missing — install Tetragon first (see README)"
command -v systemctl >/dev/null || die "systemctl(1) missing"

EVENT_LOG=$(toml_get event_log_path "$CONFIG_FILE" || echo "/var/log/tetragon/events.json")
POLICY_DIR=$(toml_get policy_dir    "$CONFIG_FILE" || echo "/etc/tetragon/tetragon.tp.d")
METRICS_ADDR=$(toml_get metrics_address "$CONFIG_FILE" || echo "localhost:2112")
CONFIG_PATH=$(toml_get config_path  "$CONFIG_FILE" || echo "/etc/tetragon/tetragon.yaml")
SERVICE_UNIT=$(toml_get service_unit "$CONFIG_FILE" || echo "tetragon.service")
REQUIRE_SIGNED=$(toml_get require_signed_policies "$CONFIG_FILE" || echo "false")

# SDD-004 F-2026-024 follow-up: when require_signed_policies=true,
# refuse to (re)start tetragon if any policy in $POLICY_DIR is
# unsigned or its signature doesn't verify under the daemon's
# configured public key. Verification re-uses
# `selfdefctl keys verify` (which reads
# [security].signing_public_key_file from /etc/selfdef/selfdef.toml)
# so operators don't have to plumb a second key path.
if [[ "$REQUIRE_SIGNED" == "true" ]]; then
    if ! command -v selfdefctl >/dev/null; then
        die "require_signed_policies=true but selfdefctl is not on PATH"
    fi
    if [[ -d "$POLICY_DIR" ]]; then
        # F-2027-006: one-shot batch verify replaces the N-spawn
        # per-file loop. `selfdefctl keys verify-dir` walks the
        # immediate *.yml/*.yaml in $POLICY_DIR, verifies each
        # against [security].signing_public_key_file, and exits
        # non-zero iff any file fails. Empty dirs verify trivially.
        if [[ "$DRY_RUN" == "1" ]]; then
            log "DRY-RUN: would verify policies in $POLICY_DIR against [security].signing_public_key_file"
        else
            if ! selfdefctl keys verify-dir "$POLICY_DIR" >/dev/null 2>&1; then
                # Re-run with output so the operator sees which
                # file(s) failed.
                selfdefctl keys verify-dir "$POLICY_DIR" || true
                die "one or more policy file(s) in $POLICY_DIR failed signature verification — refusing to (re)start tetragon"
            fi
        fi
    fi
fi

# Render to a temp file and only swap in if the bytes changed —
# avoids a service restart on a no-op apply.
NEW_CONFIG=$(mktemp)
trap 'rm -f "$NEW_CONFIG"' EXIT
render_tetragon_config "$EVENT_LOG" "$POLICY_DIR" "$METRICS_ADDR" > "$NEW_CONFIG"

changes=0

# Policy directory must exist before tetragon starts watching it.
if [[ ! -d "$POLICY_DIR" ]]; then
    run "create policy dir $POLICY_DIR" -- mkdir -p "$POLICY_DIR"
    changes=$((changes + 1))
fi

# Event log parent dir — Tetragon needs to be able to write here.
EVENT_LOG_DIR=$(dirname "$EVENT_LOG")
if [[ ! -d "$EVENT_LOG_DIR" ]]; then
    run "create event log dir $EVENT_LOG_DIR" -- mkdir -p "$EVENT_LOG_DIR"
    changes=$((changes + 1))
fi

# Config: only swap if content actually changed.
CONFIG_DIR=$(dirname "$CONFIG_PATH")
if [[ ! -d "$CONFIG_DIR" ]]; then
    run "create config dir $CONFIG_DIR" -- mkdir -p "$CONFIG_DIR"
    changes=$((changes + 1))
fi
if [[ ! -f "$CONFIG_PATH" ]] || ! cmp -s "$NEW_CONFIG" "$CONFIG_PATH"; then
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY-RUN: would write $CONFIG_PATH"
        log "$(sed 's/^/    /' "$NEW_CONFIG")"
    else
        install -m 0644 "$NEW_CONFIG" "$CONFIG_PATH"
    fi
    changes=$((changes + 1))
fi

# Service: ensure enabled. Restart only when something changed.
if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY-RUN: would enable + start $SERVICE_UNIT"
    [[ "$changes" -gt 0 ]] && log "DRY-RUN: would restart $SERVICE_UNIT due to config change"
else
    systemctl enable "$SERVICE_UNIT" >/dev/null 2>&1 || \
        log "warning: could not enable $SERVICE_UNIT (continuing)"
    if [[ "$changes" -gt 0 ]]; then
        systemctl restart "$SERVICE_UNIT" || \
            die "$SERVICE_UNIT failed to (re)start"
    else
        systemctl start "$SERVICE_UNIT" >/dev/null 2>&1 || \
            die "$SERVICE_UNIT failed to start"
    fi
fi

if [[ "$changes" -eq 0 ]]; then
    emit_status "ok" "tetragon already at desired state"
else
    emit_status "ok" "tetragon configured ($changes change(s)); metrics on ${METRICS_ADDR}, events to ${EVENT_LOG}"
fi
