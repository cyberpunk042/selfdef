#!/usr/bin/env bash
# agent-guard — check. Read-only.
#
# Walks the configured policy set and verifies each enabled policy
# is present in tetragon's policy_dir with the action that the
# current profile demands. A disabled policy must NOT be present.

set -euo pipefail

MODULE="agent-guard"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_AGENT_GUARD_CONFIG:-/etc/selfdef/modules/agent-guard.toml}"
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

ETC_WRITE_ENABLED=$(toml_get etc_write_enabled "$CONFIG_FILE" || echo "true")
ETC_WRITE_ACTION=$(toml_get  etc_write_action  "$CONFIG_FILE" || echo "default")
SHELL_EXEC_ENABLED=$(toml_get shell_exec_enabled "$CONFIG_FILE" || echo "true")
SHELL_EXEC_ACTION=$(toml_get  shell_exec_action  "$CONFIG_FILE" || echo "default")
EGRESS_ENABLED=$(toml_get egress_enabled "$CONFIG_FILE" || echo "true")
EGRESS_ACTION=$(toml_get  egress_action  "$CONFIG_FILE" || echo "default")
SM_ENABLED=$(toml_get securemessage_enabled "$CONFIG_FILE" || echo "true")
SM_ACTION=$(toml_get  securemessage_action  "$CONFIG_FILE" || echo "default")
SM_ENDPOINT=$(toml_get securemessage_endpoint "$CONFIG_FILE" || echo "")
# Mirrors apply.sh: with no endpoint set, the stub stays Post
# regardless of profile / override.
if [[ -z "$SM_ENDPOINT" ]]; then
    SM_ACTION="post"
fi

GPU_ENABLED=$(toml_get gpu_device_enabled "$CONFIG_FILE" || echo "true")
GPU_ACTION=$(toml_get  gpu_device_action  "$CONFIG_FILE" || echo "default")

declare -a CHECK=(
    "etc-write-guard:$ETC_WRITE_ENABLED:$ETC_WRITE_ACTION"
    "container-shell-guard:$SHELL_EXEC_ENABLED:$SHELL_EXEC_ACTION"
    "egress-guard:$EGRESS_ENABLED:$EGRESS_ACTION"
    "securemessage-guard:$SM_ENABLED:$SM_ACTION"
    "gpu-device-guard:$GPU_ENABLED:$GPU_ACTION"
)

missing=0
unexpected=0
present=0

for entry in "${CHECK[@]}"; do
    IFS=':' read -r name enabled override <<<"$entry"
    dst="${POLICY_DIR}/selfdef-agent-${name}.yaml"
    if [[ "$enabled" != "true" ]]; then
        if [[ -f "$dst" ]]; then
            log "stale policy still present: $dst"
            unexpected=$((unexpected + 1))
        fi
        continue
    fi
    if [[ ! -f "$dst" ]]; then
        log "policy missing: $dst"
        missing=$((missing + 1))
        continue
    fi
    expected_action=$(resolve_action "$PROFILE" "$override")
    # The action keyword appears exactly once per policy (the
    # selectors we ship have one matchActions each). grep -m1 finds
    # the first match — if it doesn't equal the expected action,
    # the policy on disk is at the wrong setting.
    found=$(grep -m1 -E '^[[:space:]]+- action:' "$dst" | awk '{print $3}')
    if [[ "$found" != "$expected_action" ]]; then
        log "policy $dst has action=$found, expected $expected_action"
        missing=$((missing + 1))
        continue
    fi
    present=$((present + 1))
done

if [[ "$missing" -gt 0 ]] || [[ "$unexpected" -gt 0 ]]; then
    emit_status "failed" "agent-guard drift: missing=$missing unexpected=$unexpected (profile=$PROFILE)"
    exit 1
fi

emit_status "ok" "agent-guard profile=$PROFILE policies=$present"
