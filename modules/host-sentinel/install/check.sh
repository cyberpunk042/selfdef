#!/usr/bin/env bash
# host-sentinel — check. Read-only.
#
# Verifies each enabled policy is present in tetragon's policy_dir
# with the action that the current profile demands.

set -euo pipefail

MODULE="host-sentinel"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_HOST_SENTINEL_CONFIG:-/etc/selfdef/modules/host-sentinel.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "audit")

TG_CFG="${SELFDEF_TETRAGON_CONFIG:-/etc/selfdef/modules/tetragon.toml}"
POLICY_DIR="/etc/tetragon/tetragon.tp.d"
if [[ -r "$TG_CFG" ]]; then
    POLICY_DIR=$(toml_get policy_dir "$TG_CFG" || echo "$POLICY_DIR")
fi

KMOD_ENABLED=$(toml_get        kmod_watch_enabled       "$CONFIG_FILE" || echo "true")
LD_PRELOAD_ENABLED=$(toml_get   ld_preload_watch_enabled "$CONFIG_FILE" || echo "true")

check_one() {
    local name="$1"
    local enabled="$2"
    local expected_action="$3"
    local f="${POLICY_DIR}/${name}.yaml"

    if [[ "$enabled" != "true" ]]; then
        if [[ -f "$f" ]]; then
            emit_status "drift" "${name} disabled in config but file present"
            return 1
        fi
        return 0
    fi

    [[ -f "$f" ]] || { emit_status "drift" "${name} enabled but file missing: $f"; return 1; }
    if ! grep -q "action: ${expected_action}" "$f"; then
        emit_status "drift" "${name} present but action ≠ ${expected_action}"
        return 1
    fi
}

drift=0
KMOD_ACTION="Post"
LD_PRELOAD_ACTION="Post"
[[ "$PROFILE" == "enforce" ]] && LD_PRELOAD_ACTION="Sigkill"

check_one "selfdef-host-kmod-watch"        "$KMOD_ENABLED"       "$KMOD_ACTION"       || drift=$((drift + 1))
check_one "selfdef-host-ld-preload-watch"  "$LD_PRELOAD_ENABLED" "$LD_PRELOAD_ACTION" || drift=$((drift + 1))

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "host-sentinel profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "host-sentinel profile=$PROFILE no drift"
