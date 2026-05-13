#!/usr/bin/env bash
# agent-guard — uninstall.
#
# Removes every policy YAML this module owns from tetragon's
# policy_dir. Leaves the policy_dir itself alone (tetragon owns
# that). Idempotent. SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="agent-guard"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_AGENT_GUARD_CONFIG:-/etc/selfdef/modules/agent-guard.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

# SDD-006 v2 / F-2026-050: rendered-file enumeration via the
# shared lib's manifest. Pre-follow-up this script hand-listed
# every policy name; a new policy meant editing two scripts in
# lockstep, and forgetting one orphaned the rendered file.
# Now apply.sh records every file it writes; we just iterate
# the manifest.
#
# Fallback: pre-v2 installs that never recorded a manifest get
# the old hand-enumerated cleanup as a one-shot migration path
# so the first post-upgrade uninstall isn't a no-op.

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

if [[ "$manifest_count" -eq 0 ]]; then
    # Migration path: the manifest is empty (either an
    # uninstall-without-apply OR a pre-v2 install). Fall back
    # to the old hand-enumerated list one last time so existing
    # deployments don't leave orphan files behind.
    TG_CFG="${SELFDEF_TETRAGON_CONFIG:-/etc/selfdef/modules/tetragon.toml}"
    POLICY_DIR="/etc/tetragon/tetragon.tp.d"
    if [[ -r "$TG_CFG" ]]; then
        POLICY_DIR=$(toml_get policy_dir "$TG_CFG" || echo "$POLICY_DIR")
    fi
    for name in etc-write-guard container-shell-guard egress-guard securemessage-guard gpu-device-guard; do
        dst="${POLICY_DIR}/selfdef-agent-${name}.yaml"
        if [[ -f "$dst" ]]; then
            run "remove $dst (legacy enum)" -- rm -f "$dst"
            removed=$((removed + 1))
        fi
    done
fi

module_clear_manifest

emit_status "ok" "agent-guard removed $removed policy file(s)"
