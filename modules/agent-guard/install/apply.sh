#!/usr/bin/env bash
# agent-guard — apply.
#
# Renders four TracingPolicies into Tetragon's policy_dir with
# per-policy action overrides and the operator's egress allowlist /
# SecureMessage endpoint spliced in. Tetragon picks up new policy
# files automatically (it watches the dir).
#
# Idempotent: re-running with the same config rewrites byte-identical
# files. Dry-run aware.

set -euo pipefail

MODULE="agent-guard"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_AGENT_GUARD_CONFIG:-/etc/selfdef/modules/agent-guard.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
POLICIES_SRC="${SELFDEF_AGENT_GUARD_POLICIES:-${MODULE_DIR}/policies}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$POLICIES_SRC" ]] || die "policy source dir missing: $POLICIES_SRC"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "audit")
case "$PROFILE" in
    audit|enforce) ;;
    *) die "profile must be audit|enforce, got '$PROFILE'" ;;
esac

# Container-scope: `container` (default, uses matchNamespaces on
# Pid != host_ns — works on any container runtime) vs `pod-label`
# (uses matchPodSelector — k8s-only, narrower because it can match
# specific agent pods).
SCOPE=$(toml_get scope "$CONFIG_FILE" || echo "container")
case "$SCOPE" in
    container|pod-label) ;;
    *) die "scope must be container|pod-label, got '$SCOPE'" ;;
esac
POD_LABEL_KEY=$(toml_get pod_label_key   "$CONFIG_FILE" || echo "")
POD_LABEL_VALUE=$(toml_get pod_label_value "$CONFIG_FILE" || echo "")
if [[ "$SCOPE" == "pod-label" ]]; then
    [[ -n "$POD_LABEL_KEY"   ]] || die "scope=pod-label requires pod_label_key"
    [[ -n "$POD_LABEL_VALUE" ]] || die "scope=pod-label requires pod_label_value"
fi

# Pull tetragon's policy_dir from *its* config so we never drift.
TG_CFG="${SELFDEF_TETRAGON_CONFIG:-/etc/selfdef/modules/tetragon.toml}"
POLICY_DIR="/etc/tetragon/tetragon.tp.d"
if [[ -r "$TG_CFG" ]]; then
    POLICY_DIR=$(toml_get policy_dir "$TG_CFG" || echo "$POLICY_DIR")
fi
if [[ ! -d "$POLICY_DIR" ]]; then
    run "create $POLICY_DIR" -- mkdir -p "$POLICY_DIR"
fi

# Per-policy config — flags + actions.
ETC_WRITE_ENABLED=$(toml_get etc_write_enabled  "$CONFIG_FILE" || echo "true")
ETC_WRITE_ACTION=$(toml_get  etc_write_action   "$CONFIG_FILE" || echo "default")

SHELL_EXEC_ENABLED=$(toml_get shell_exec_enabled "$CONFIG_FILE" || echo "true")
SHELL_EXEC_ACTION=$(toml_get  shell_exec_action  "$CONFIG_FILE" || echo "default")

EGRESS_ENABLED=$(toml_get egress_enabled   "$CONFIG_FILE" || echo "true")
EGRESS_ACTION=$(toml_get  egress_action    "$CONFIG_FILE" || echo "default")
EGRESS_ALLOWLIST=$(toml_get egress_allowlist "$CONFIG_FILE" || echo "")

SM_ENABLED=$(toml_get securemessage_enabled  "$CONFIG_FILE" || echo "true")
SM_ACTION=$(toml_get  securemessage_action   "$CONFIG_FILE" || echo "default")
SM_ENDPOINT=$(toml_get securemessage_endpoint "$CONFIG_FILE" || echo "")

# Until the SecureMessage endpoint exists on the host, the policy
# stub is dormant — its selector matches a placeholder string that
# never appears as a real path. Killing on a dormant stub would be
# confusing if it ever triggered, so when the endpoint is unset we
# force the action to Post regardless of profile / override.
if [[ -z "$SM_ENDPOINT" ]]; then
    SM_ACTION="post"
fi

GPU_ENABLED=$(toml_get gpu_device_enabled  "$CONFIG_FILE" || echo "true")
GPU_ACTION=$(toml_get  gpu_device_action   "$CONFIG_FILE" || echo "default")
GPU_PATHS=$(toml_get   gpu_device_paths    "$CONFIG_FILE" || echo "")
GPU_ALLOWLIST=$(toml_get gpu_device_allowlist "$CONFIG_FILE" || echo "")

# Each policy is a (source-name, enabled, action-override, post-render-hook) tuple.
declare -a POLICIES=(
    "etc-write-guard:$ETC_WRITE_ENABLED:$ETC_WRITE_ACTION:"
    "container-shell-guard:$SHELL_EXEC_ENABLED:$SHELL_EXEC_ACTION:"
    "egress-guard:$EGRESS_ENABLED:$EGRESS_ACTION:egress"
    "securemessage-guard:$SM_ENABLED:$SM_ACTION:securemessage"
    "gpu-device-guard:$GPU_ENABLED:$GPU_ACTION:gpu"
)

changes=0
installed=0
disabled=0

for entry in "${POLICIES[@]}"; do
    IFS=':' read -r name enabled override post_hook <<<"$entry"
    src="${POLICIES_SRC}/${name}.yaml"
    dst="${POLICY_DIR}/selfdef-agent-${name}.yaml"

    if [[ "$enabled" != "true" ]]; then
        # Disabled in config → make sure no stale render is left behind.
        if [[ -f "$dst" ]]; then
            run "remove disabled policy $dst" -- rm -f "$dst"
            changes=$((changes + 1))
        fi
        disabled=$((disabled + 1))
        continue
    fi

    action=$(resolve_action "$PROFILE" "$override")
    tmp=$(mktemp)
    render_policy "$src" "$tmp" "$action"
    case "$post_hook" in
        egress)        render_egress_allowlist "$tmp" "$EGRESS_ALLOWLIST" ;;
        securemessage) render_securemessage_endpoint "$tmp" "$SM_ENDPOINT" ;;
        gpu)           render_gpu_policy "$tmp" "$GPU_PATHS" "$GPU_ALLOWLIST" ;;
    esac
    # Container-scope swap runs last — it rewrites the
    # matchNamespaces anchor that earlier renders (e.g. the
    # gpu_policy matchBinaries-drop) depend on.
    if [[ "$SCOPE" == "pod-label" ]]; then
        render_pod_scope "$tmp" "$POD_LABEL_KEY" "$POD_LABEL_VALUE"
    fi

    if [[ ! -f "$dst" ]] || ! cmp -s "$tmp" "$dst"; then
        if [[ "$DRY_RUN" == "1" ]]; then
            log "DRY-RUN: would write $dst (action=$action)"
        else
            install -m 0644 "$tmp" "$dst"
        fi
        changes=$((changes + 1))
    fi
    rm -f "$tmp"
    installed=$((installed + 1))
done

emit_status "ok" "agent-guard profile=$PROFILE installed=$installed disabled=$disabled changes=$changes"
