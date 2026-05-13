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

TG_CFG="${SELFDEF_TETRAGON_CONFIG:-/etc/selfdef/modules/tetragon.toml}"
POLICY_DIR="/etc/tetragon/tetragon.tp.d"
if [[ -r "$TG_CFG" ]]; then
    POLICY_DIR=$(toml_get policy_dir "$TG_CFG" || echo "$POLICY_DIR")
fi

removed=0
for name in etc-write-guard container-shell-guard egress-guard securemessage-guard gpu-device-guard; do
    dst="${POLICY_DIR}/selfdef-agent-${name}.yaml"
    if [[ -f "$dst" ]]; then
        run "remove $dst" -- rm -f "$dst"
        removed=$((removed + 1))
    fi
done

emit_status "ok" "agent-guard removed $removed policy file(s)"
